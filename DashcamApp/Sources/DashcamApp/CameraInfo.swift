import AVFoundation

enum CameraPosition: String, CaseIterable {
    case frontWide = "Front Wide"
    case frontTelephoto = "Front Zoom"

    var position: AVCaptureDevice.Position {
        return .front
    }

    var deviceType: AVCaptureDevice.DeviceType {
        switch self {
        case .frontWide:
            return .builtInWideAngleCamera
        case .frontTelephoto:
            return .builtInTelephotoCamera
        }
    }

    var filePrefix: String {
        switch self {
        case .frontWide:
            return "front_wide"
        case .frontTelephoto:
            return "front_zoom"
        }
    }
}

enum CameraSetupError: Error {
    case deviceNotAvailable
    case inputCreationFailed
    case outputCreationFailed
    case configurationFailed
    case invalidSession
}

class CameraRecorderDelegate: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate, AVCaptureAudioDataOutputSampleBufferDelegate {
    var realtimeVideoWriter: RealtimeVideoWriter?
    var watermarkGenerator: WatermarkTextGenerator?

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        if CMSampleBufferDataIsReady(sampleBuffer) {
            if output is AVCaptureVideoDataOutput {
                handleVideoSample(sampleBuffer)
            } else if output is AVCaptureAudioDataOutput {
                handleAudioSample(sampleBuffer)
            }
        }
    }

    private func handleVideoSample(_ sampleBuffer: CMSampleBuffer) {
        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        let timestamp = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        let watermarkText = watermarkGenerator?.generateFullWatermarkText() ?? ""
        realtimeVideoWriter?.processAndWriteFrame(pixelBuffer, timestamp: timestamp, watermarkText: watermarkText)
    }

    private func handleAudioSample(_ sampleBuffer: CMSampleBuffer) {
        realtimeVideoWriter?.writeAudioSample(sampleBuffer)
    }
}

struct CameraRecorder {
    let position: CameraPosition
    var captureSession: AVCaptureSession?
    var videoOutput: AVCaptureMovieFileOutput?
    var videoDataOutput: AVCaptureVideoDataOutput?
    var audioDataOutput: AVCaptureAudioDataOutput?
    var videoInput: AVCaptureDeviceInput?
    var audioInput: AVCaptureDeviceInput?
    var realtimeVideoWriter: RealtimeVideoWriter?
    var watermarkGenerator: WatermarkTextGenerator?
    var recorderDelegate: CameraRecorderDelegate?
    var isRecording: Bool = false
    var currentURL: URL?
    var isAvailable: Bool = false
    var usingWatermark: Bool = false
    private let sessionQueue = DispatchQueue(label: "com.dashcam.camera.\(UUID().uuidString)", attributes: [], autoreleaseFrequency: .workItem)

    mutating func setupSession() -> Bool {
        let session = AVCaptureSession()

        do {
            try self.configureSession(session)
            self.captureSession = session
            self.isAvailable = true
            return true
        } catch {
            print("Camera setup error for \(self.position.rawValue): \(error)")
            self.captureSession = session
            self.isAvailable = false
            return false
        }
    }

    private mutating func configureSession(_ session: AVCaptureSession) throws {
        session.beginConfiguration()
        defer { session.commitConfiguration() }

        try validatePreset()
        session.sessionPreset = .high

        let videoDevice = try findAndConfigureVideoDevice()
        try configureVideoInput(videoDevice, to: session)
        try configureVideoOutput(to: session, with: videoDevice)

        sessionQueue.asyncAfter(deadline: .now() + 0.1) {
            session.startRunning()
        }
    }

    private func validatePreset() throws {
        let session = AVCaptureSession()
        if !session.canSetSessionPreset(.high) {
            throw CameraSetupError.configurationFailed
        }
    }

    private func findAndConfigureVideoDevice() throws -> AVCaptureDevice {
        guard let videoDevice = AVCaptureDevice.default(
            position.deviceType,
            for: .video,
            position: position.position
        ) else {
            throw CameraSetupError.deviceNotAvailable
        }

        if !videoDevice.isConnected {
            throw CameraSetupError.deviceNotAvailable
        }

        return videoDevice
    }

    private mutating func configureVideoInput(_ device: AVCaptureDevice, to session: AVCaptureSession) throws {
        let videoInput = try AVCaptureDeviceInput(device: device)
        self.videoInput = videoInput

        guard session.canAddInput(videoInput) else {
            throw CameraSetupError.inputCreationFailed
        }

        session.addInput(videoInput)
    }

    private mutating func configureVideoOutput(to session: AVCaptureSession, with device: AVCaptureDevice) throws {
        let movieOutput = AVCaptureMovieFileOutput()

        guard session.canAddOutput(movieOutput) else {
            throw CameraSetupError.outputCreationFailed
        }

        session.addOutput(movieOutput)
        self.videoOutput = movieOutput

        try configureVideoConnection(for: movieOutput)
        configureVideoCodec(for: movieOutput)
        configureVideoStabilization(for: movieOutput)
        configureHDRVideo(for: movieOutput, device: device)
        configureFocusAndExposure(device: device)
    }

    private func configureVideoConnection(for output: AVCaptureMovieFileOutput) throws {
        guard let videoConnection = output.connection(with: .video) else {
            throw CameraSetupError.configurationFailed
        }

        if videoConnection.isVideoStabilizationSupported {
            videoConnection.preferredVideoStabilizationMode = .cinematic
        }

        // Set video orientation to portrait (0 degrees)
        if #available(iOS 17.0, *) {
            videoConnection.videoRotationAngle = 0
        } else {
            videoConnection.videoOrientation = .portrait
        }

        videoConnection.isVideoMirrored = (position == .frontWide || position == .frontTelephoto)

        if !videoConnection.isActive {
            throw CameraSetupError.configurationFailed
        }
    }

    private func configureVideoCodec(for output: AVCaptureMovieFileOutput) {
        let codecManager = VideoCodecManager.shared
        let videoSettings = codecManager.getVideoSettings()

        // Video codec settings are applied through the session preset.
        // The settings dictionary is used for watermarked recording via RealtimeVideoWriter.
        print("Video codec configured: \(videoSettings[AVVideoCodecKey] ?? "unknown")")
    }

    private func configureVideoStabilization(for output: AVCaptureMovieFileOutput) {
        guard let connection = output.connection(with: .video) else { return }

        if connection.isVideoStabilizationSupported {
            connection.preferredVideoStabilizationMode = .cinematic
        }
    }

    private func configureHDRVideo(for output: AVCaptureMovieFileOutput, device: AVCaptureDevice) {
        if #available(iOS 17.0, *) {
            guard device.isVideoHDRSupported else { return }

            do {
                try device.lockForConfiguration()
                defer { device.unlockForConfiguration() }
                device.isVideoHDREnabled = true
            } catch {
                print("Warning: Could not enable HDR video: \(error)")
            }
        }
    }

    private func configureFocusAndExposure(device: AVCaptureDevice) {
        do {
            try device.lockForConfiguration()
            defer { device.unlockForConfiguration() }

            if device.isFocusModeSupported(.continuousAutoFocus) {
                device.focusMode = .continuousAutoFocus
            }

            if device.isFocusPointOfInterestSupported {
                device.focusPointOfInterest = CGPoint(x: 0.5, y: 0.5)
            }

            if device.isExposureModeSupported(.continuousAutoExposure) {
                device.exposureMode = .continuousAutoExposure
            }

            if device.isExposurePointOfInterestSupported {
                device.exposurePointOfInterest = CGPoint(x: 0.5, y: 0.5)
            }

            if device.isWhiteBalanceModeSupported(.continuousAutoWhiteBalance) {
                device.whiteBalanceMode = .continuousAutoWhiteBalance
            }

            // Note: isAutoFocusSystemSupported was removed in iOS 18
            // Continuous auto-focus is set above and should be sufficient

            if device.isLowLightBoostSupported {
                device.automaticallyEnablesLowLightBoostWhenAvailable = true
            }

            if device.isSubjectAreaChangeMonitoringEnabled == false {
                device.isSubjectAreaChangeMonitoringEnabled = true
            }
        } catch {
            print("Warning: Could not configure focus/exposure: \(error)")
        }
    }

    mutating func startRecording(to url: URL, delegate: AVCaptureFileOutputRecordingDelegate, withWatermark watermarkGenerator: WatermarkTextGenerator? = nil) {
        guard captureSession?.isRunning == true else {
            print("Error: Camera not ready for recording")
            return
        }

        sessionQueue.async {
            if let videoOutput = self.videoOutput, videoOutput.isRecording {
                videoOutput.stopRecording()
            }

            self.currentURL = url

            if let watermarkGenerator = watermarkGenerator {
                let recorderDelegate = CameraRecorderDelegate()
                recorderDelegate.watermarkGenerator = watermarkGenerator
                recorderDelegate.realtimeVideoWriter = self.realtimeVideoWriter
                self.recorderDelegate = recorderDelegate

                self.setupWatermarkedRecording(to: url, delegate: delegate, watermarkGenerator: watermarkGenerator)
            } else if let videoOutput = self.videoOutput {
                videoOutput.startRecording(to: url, recordingDelegate: delegate)
            }

            self.isRecording = true
        }
    }

    private mutating func setupWatermarkedRecording(to url: URL, delegate: AVCaptureFileOutputRecordingDelegate, watermarkGenerator: WatermarkTextGenerator) {
        self.watermarkGenerator = watermarkGenerator
        self.usingWatermark = true

        let writer = RealtimeVideoWriter()
        self.realtimeVideoWriter = writer

        let videoSettings: [String: Any] = [
            AVVideoCodecKey: AVVideoCodecType.h264,
            AVVideoWidthKey: 1920,
            AVVideoHeightKey: 1080
        ]

        let audioSettings: [String: Any] = [
            AVFormatIDKey: kAudioFormatMPEG4AAC,
            AVNumberOfChannelsKey: 2,
            AVSampleRateKey: 44100
        ]

        do {
            try writer.startRecording(to: url, videoSettings: videoSettings, audioSettings: audioSettings, sourceVideoTrack: videoInput)

            sessionQueue.async {
                self.setupDataOutputs()
            }

            print("Watermarked recording started for \(position.rawValue)")
        } catch {
            print("Failed to start watermarked recording: \(error)")
        }
    }

    private mutating func setupDataOutputs() {
        guard let session = captureSession else { return }

        let videoDataOutput = AVCaptureVideoDataOutput()
        videoDataOutput.setSampleBufferDelegate(recorderDelegate, queue: sessionQueue)
        videoDataOutput.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA]
        videoDataOutput.alwaysDiscardsLateVideoFrames = true

        if session.canAddOutput(videoDataOutput) {
            session.addOutput(videoDataOutput)
            self.videoDataOutput = videoDataOutput
        }

        let audioDataOutput = AVCaptureAudioDataOutput()
        audioDataOutput.setSampleBufferDelegate(recorderDelegate, queue: sessionQueue)

        if session.canAddOutput(audioDataOutput) {
            session.addOutput(audioDataOutput)
            self.audioDataOutput = audioDataOutput
        }
    }

    mutating func stopRecording() {
        sessionQueue.async {
            if let realtimeWriter = self.realtimeVideoWriter, self.usingWatermark {
                if let videoDataOutput = self.videoDataOutput {
                    self.captureSession?.removeOutput(videoDataOutput)
                    self.videoDataOutput = nil
                }
                if let audioDataOutput = self.audioDataOutput {
                    self.captureSession?.removeOutput(audioDataOutput)
                    self.audioDataOutput = nil
                }

                realtimeWriter.finishWriting { success, error in
                    if success {
                        print("Watermarked video saved successfully for \(self.position.rawValue)")
                    } else if let error = error {
                        print("Error saving watermarked video: \(error)")
                    }
                }
                self.realtimeVideoWriter = nil
                self.watermarkGenerator = nil
                self.recorderDelegate = nil
                self.usingWatermark = false
            } else if let videoOutput = self.videoOutput, videoOutput.isRecording {
                videoOutput.stopRecording()
            }
            self.isRecording = false
        }
    }

    mutating func cleanup() {
        sessionQueue.async {
            if let session = self.captureSession {
                if session.isRunning {
                    session.stopRunning()
                }
                if let videoDataOutput = self.videoDataOutput {
                    session.removeOutput(videoDataOutput)
                }
                if let audioDataOutput = self.audioDataOutput {
                    session.removeOutput(audioDataOutput)
                }
            }

            self.videoInput = nil
            self.audioInput = nil
            self.videoOutput = nil
            self.videoDataOutput = nil
            self.audioDataOutput = nil
            self.captureSession = nil
            self.recorderDelegate = nil
            self.realtimeVideoWriter = nil
        }
    }

    mutating func setFrameRate(_ fps: Int32) {
        guard let videoInput = videoInput else { return }

        let device = videoInput.device
        let targetDuration = CMTime(value: 1, timescale: fps)

        do {
            try device.lockForConfiguration()
            defer { device.unlockForConfiguration() }

            device.activeVideoMinFrameDuration = targetDuration
            device.activeVideoMaxFrameDuration = targetDuration

            print("Frame rate set to \(fps) fps for \(position.rawValue)")
        } catch {
            print("Error setting frame rate for \(position.rawValue): \(error)")
        }
    }

    mutating func setSlowMotionFrameRate(_ fps: Int32 = 60) {
        guard let videoInput = videoInput else { return }

        let device = videoInput.device
        let targetDuration = CMTime(value: 1, timescale: fps)

        do {
            try device.lockForConfiguration()
            defer { device.unlockForConfiguration() }

            device.activeVideoMinFrameDuration = targetDuration
            device.activeVideoMaxFrameDuration = targetDuration

            print("Slow-motion frame rate set to \(fps) fps for \(position.rawValue)")
        } catch {
            print("Error setting slow-motion frame rate for \(position.rawValue): \(error)")
        }
    }

    func getSessionStatus() -> String {
        if !isAvailable {
            return "Unavailable"
        }
        if captureSession?.isRunning == false {
            return "Setup Failed"
        }
        if isRecording {
            return "Recording"
        }
        return "Ready"
    }
}
