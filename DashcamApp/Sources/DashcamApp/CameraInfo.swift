import AVFoundation

enum CameraPosition: String, CaseIterable {
    case backWide = "Back Wide"
    case backTelephoto = "Back Telephoto"
    case frontWide = "Front Camera"

    var position: AVCaptureDevice.Position {
        switch self {
        case .backWide, .backTelephoto:
            return .back
        case .frontWide:
            return .front
        }
    }

    var deviceType: AVCaptureDevice.DeviceType {
        switch self {
        case .backWide:
            return .builtInWideAngleCamera
        case .backTelephoto:
            return .builtInTelephotoCamera
        case .frontWide:
            return .builtInWideAngleCamera
        }
    }

    var filePrefix: String {
        switch self {
        case .backWide:
            return "back_wide"
        case .backTelephoto:
            return "back_zoom"
        case .frontWide:
            return "front_wide"
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
    private var videoFrameCount = 0
    private var audioFrameCount = 0
    private var lastLogTime = Date()

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        if CMSampleBufferDataIsReady(sampleBuffer) {
            if output is AVCaptureVideoDataOutput {
                handleVideoSample(sampleBuffer)
            } else if output is AVCaptureAudioDataOutput {
                handleAudioSample(sampleBuffer)
            }
        } else {
            if videoFrameCount == 0 {
                print("[CameraRecorder] ⚠️ Received sample buffer that is not ready")
            }
        }
    }

    private func handleVideoSample(_ sampleBuffer: CMSampleBuffer) {
        if videoFrameCount == 0 {
            print("[CameraRecorder] ✅ Received first video frame")
            lastLogTime = Date()
        }
        videoFrameCount += 1

        // Log every 300 frames (roughly every 10 seconds at 30fps)
        if videoFrameCount % 300 == 0 {
            print("[CameraRecorder] Video frames captured: \(videoFrameCount)")
        }

        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else {
            if videoFrameCount <= 3 {
                print("[CameraRecorder] ❌ Could not get pixel buffer from sample \(videoFrameCount)")
            }
            return
        }

        let timestamp = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        let watermarkText = watermarkGenerator?.generateFullWatermarkText() ?? ""

        if realtimeVideoWriter == nil {
            if videoFrameCount <= 3 {
                print("[CameraRecorder] ❌ Video writer is nil - cannot write frame \(videoFrameCount)")
            }
        } else {
            realtimeVideoWriter?.processAndWriteFrame(pixelBuffer, timestamp: timestamp, watermarkText: watermarkText)
        }
    }

    private func handleAudioSample(_ sampleBuffer: CMSampleBuffer) {
        if audioFrameCount == 0 {
            print("[CameraRecorder] ✅ Received first audio sample")
        }
        audioFrameCount += 1

        if audioFrameCount % 1500 == 0 {
            print("[CameraRecorder] Audio samples captured: \(audioFrameCount)")
        }

        if realtimeVideoWriter == nil {
            if audioFrameCount <= 3 {
                print("[CameraRecorder] ❌ Video writer is nil - cannot write audio sample \(audioFrameCount)")
            }
        } else {
            realtimeVideoWriter?.writeAudioSample(sampleBuffer)
        }
    }
}

class CameraRecorder {
    let position: CameraPosition
    var videoOutput: AVCaptureMovieFileOutput?
    var videoDataOutput: AVCaptureVideoDataOutput?
    var audioDataOutput: AVCaptureAudioDataOutput?
    var realtimeVideoWriter: RealtimeVideoWriter?
    var watermarkGenerator: WatermarkTextGenerator?
    var recorderDelegate: CameraRecorderDelegate?
    var isRecording: Bool = false
    var currentURL: URL?
    var isAvailable: Bool = false
    var usingWatermark: Bool = false

    private let multiCamSession = MultiCameraSessionManager.shared

    init(position: CameraPosition) {
        self.position = position
    }

    func setupSession() -> Bool {
        print("[CameraRecorder] ========== SETTING UP CAMERA: \(position.rawValue) ==========")

        do {
            // Add camera to shared multi-camera session
            try multiCamSession.addCamera(position)
            print("[CameraRecorder] ✅ \(position.rawValue) added to multi-camera session")

            // Configure this camera's outputs
            try configureOutputs()
            print("[CameraRecorder] ✅ \(position.rawValue) outputs configured")

            self.isAvailable = true
            print("[CameraRecorder] ✅ \(position.rawValue) setup complete - Hardware cost: \(String(format: "%.2f", multiCamSession.hardwareCost))")
            return true
        } catch {
            print("[CameraRecorder] ❌ Camera setup error for \(self.position.rawValue): \(error)")
            self.isAvailable = false
            return false
        }
    }

    private func configureOutputs() throws {
        print("[CameraRecorder] \(position.rawValue): Configuring outputs for multi-camera session")

        // Add movie file output
        try multiCamSession.addMovieFileOutput(for: position)
        self.videoOutput = multiCamSession.getMovieFileOutput(for: position)
        print("[CameraRecorder] ✅ Movie file output configured")

        // Add video data output with recorder delegate if watermarking is enabled
        if let recorderDelegate = recorderDelegate {
            try multiCamSession.addVideoDataOutput(for: position, delegate: recorderDelegate)
            self.videoDataOutput = multiCamSession.getVideoDataOutput(for: position)
            print("[CameraRecorder] ✅ Video data output configured for watermarking")

            try multiCamSession.addAudioDataOutput(for: position, delegate: recorderDelegate)
            self.audioDataOutput = multiCamSession.getAudioDataOutput(for: position)
            print("[CameraRecorder] ✅ Audio data output configured")
        }
    }


    func startRecording(to url: URL, delegate: AVCaptureFileOutputRecordingDelegate, withWatermark watermarkGenerator: WatermarkTextGenerator? = nil) {
        print("[Recording] ========== STARTING RECORDING FOR \(position.rawValue) ==========")

        if let videoOutput = self.videoOutput, videoOutput.isRecording {
            videoOutput.stopRecording()
        }

        self.currentURL = url

        if let watermarkGenerator = watermarkGenerator {
            self.setupWatermarkedRecording(to: url, delegate: delegate, watermarkGenerator: watermarkGenerator)
        } else if let videoOutput = self.videoOutput {
            print("[Recording] \(self.position.rawValue): ✅ Starting MovieFileOutput recording to \(url.lastPathComponent)")
            videoOutput.startRecording(to: url, recordingDelegate: delegate)
        } else {
            print("[Recording] \(self.position.rawValue): ❌ No video output available")
            return
        }

        // Start the shared multi-camera session
        multiCamSession.startSession()

        self.isRecording = true
        print("[Recording] \(self.position.rawValue): ✅ Recording started, hardware cost: \(String(format: "%.2f", multiCamSession.hardwareCost))")
    }

    private func setupWatermarkedRecording(to url: URL, delegate: AVCaptureFileOutputRecordingDelegate, watermarkGenerator: WatermarkTextGenerator) {
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
            try writer.startRecording(to: url, videoSettings: videoSettings, audioSettings: audioSettings, sourceVideoTrack: nil)

            let recorderDelegate = CameraRecorderDelegate()
            recorderDelegate.watermarkGenerator = watermarkGenerator
            recorderDelegate.realtimeVideoWriter = self.realtimeVideoWriter
            self.recorderDelegate = recorderDelegate

            print("[Recording] \(position.rawValue): ✅ Watermarked recording started")
        } catch {
            print("[Recording] \(position.rawValue): ❌ Failed to start watermarked recording: \(error)")
        }
    }

    func stopRecording() {
        print("[Recording] ========== STOPPING RECORDING FOR \(position.rawValue) ==========")

        if let realtimeWriter = self.realtimeVideoWriter, self.usingWatermark {
            realtimeWriter.finishWriting { success, error in
                if success {
                    print("[Recording] \(self.position.rawValue): ✅ Watermarked video saved successfully")
                } else if let error = error {
                    print("[Recording] \(self.position.rawValue): ❌ Error saving watermarked video: \(error)")
                }
            }
            self.realtimeVideoWriter = nil
            self.watermarkGenerator = nil
            self.recorderDelegate = nil
            self.usingWatermark = false
        } else if let videoOutput = self.videoOutput, videoOutput.isRecording {
            print("[Recording] \(self.position.rawValue): Stopping movie file output")
            videoOutput.stopRecording()
        }

        // Stop the shared multi-camera session
        multiCamSession.stopSession()

        self.isRecording = false
        print("[Recording] \(self.position.rawValue): ✅ Recording stopped")
    }

    func cleanup() {
        if isRecording {
            stopRecording()
        }

        self.videoOutput = nil
        self.videoDataOutput = nil
        self.audioDataOutput = nil
        self.recorderDelegate = nil
        self.realtimeVideoWriter = nil
    }


    func getSessionStatus() -> String {
        if !isAvailable {
            return "Unavailable"
        }
        if isRecording {
            return "Recording"
        }
        return "Ready"
    }
}
