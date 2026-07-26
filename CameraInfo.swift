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

struct CameraRecorder {
    let position: CameraPosition
    var captureSession: AVCaptureSession?
    var videoOutput: AVCaptureMovieFileOutput?
    var videoInput: AVCaptureDeviceInput?
    var isRecording: Bool = false
    var currentURL: URL?
    var isAvailable: Bool = false
    private let sessionQueue = DispatchQueue(label: "com.dashcam.camera.\(UUID().uuidString)", attributes: [], autoreleaseFrequency: .workItem)

    mutating func setupSession() -> Bool {
        let session = AVCaptureSession()

        var setupSuccess = false
        let semaphore = DispatchSemaphore(value: 0)

        sessionQueue.async { [self] in
            defer { semaphore.signal() }
            do {
                try self.configureSession(session)
                setupSuccess = true
            } catch {
                print("Camera setup error for \(self.position.rawValue): \(error)")
                setupSuccess = false
            }
        }

        _ = semaphore.wait(timeout: .now() + 5.0)
        self.captureSession = session
        self.isAvailable = setupSuccess
        return setupSuccess
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

        if videoConnection.isVideoOrientationSupported {
            videoConnection.videoOrientation = .portrait
        }

        videoConnection.isVideoMirrored = (position == .frontWide || position == .frontTelephoto)

        if !videoConnection.isActive {
            throw CameraSetupError.configurationFailed
        }
    }

    private func configureVideoCodec(for output: AVCaptureMovieFileOutput) {
        do {
            let codecManager = VideoCodecManager.shared
            guard let videoSettings = codecManager.getVideoSettings() as? [String: Any] else {
                return
            }

            if let audioSettings = codecManager.getAudioSettings() as? [String: Any] {
                output.setOutputSettings([AVMediaType.audio: audioSettings], for: output.connections.first)
            }

            output.setOutputSettings(videoSettings, for: output.connections.first)
        } catch {
            print("Error configuring video codec: \(error)")
        }
    }

    private func configureVideoStabilization(for output: AVCaptureMovieFileOutput) {
        guard let connection = output.connection(with: .video) else { return }

        if connection.isVideoStabilizationSupported {
            connection.preferredVideoStabilizationMode = .cinematic
        }

        if #available(iOS 17.0, *) {
            if connection.isCinematicVideoStabilizationSupported {
                connection.preferredVideoStabilizationMode = .cinematic
            }
        }
    }

    private func configureHDRVideo(for output: AVCaptureMovieFileOutput, device: AVCaptureDevice) {
        if #available(iOS 17.0, *) {
            guard device.isHDRVideoSupported else { return }

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

            if #available(iOS 16.0, *) {
                if device.isAutoFocusSystemSupported(.autofocusSystemSensorFusion) {
                    device.focusMode = .continuousAutoFocus
                }
            }

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

    mutating func startRecording(to url: URL, delegate: AVCaptureFileOutputRecordingDelegate) {
        guard let videoOutput = videoOutput, captureSession?.isRunning == true else {
            print("Error: Camera not ready for recording")
            return
        }

        sessionQueue.async {
            if videoOutput.isRecording {
                videoOutput.stopRecording()
            }

            self.currentURL = url
            videoOutput.startRecording(to: url, recordingDelegate: delegate)
            self.isRecording = true
        }
    }

    mutating func stopRecording() {
        guard let videoOutput = videoOutput else {
            return
        }

        sessionQueue.async {
            if videoOutput.isRecording {
                videoOutput.stopRecording()
                self.isRecording = false
            }
        }
    }

    func cleanup() {
        sessionQueue.async {
            if let session = self.captureSession, session.isRunning {
                session.stopRunning()
            }

            self.videoInput = nil
            self.videoOutput = nil
            self.captureSession = nil
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
