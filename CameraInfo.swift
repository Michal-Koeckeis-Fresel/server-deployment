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

struct CameraRecorder {
    let position: CameraPosition
    var captureSession: AVCaptureSession?
    var videoOutput: AVCaptureMovieFileOutput?
    var videoInput: AVCaptureDeviceInput?
    var isRecording: Bool = false
    var currentURL: URL?
    private let sessionQueue = DispatchQueue(label: "session queue", attributes: [], autoreleaseFrequency: .workItem)

    mutating func setupSession() -> Bool {
        let session = AVCaptureSession()

        sessionQueue.async { [self] in
            self.configureSession(session)
        }

        self.captureSession = session
        return true
    }

    private mutating func configureSession(_ session: AVCaptureSession) {
        session.sessionPreset = .high

        guard let videoDevice = AVCaptureDevice.default(
            position.deviceType,
            for: .video,
            position: position.position
        ) else {
            return
        }

        do {
            let videoInput = try AVCaptureDeviceInput(device: videoDevice)
            self.videoInput = videoInput

            if session.canAddInput(videoInput) {
                session.addInput(videoInput)
            }

            let movieOutput = AVCaptureMovieFileOutput()

            if session.canAddOutput(movieOutput) {
                session.addOutput(movieOutput)

                configureVideoConnection(for: movieOutput)
                configureVideoCodec(for: movieOutput)
                configureVideoStabilization(for: movieOutput)
            }

            self.videoOutput = movieOutput

            sessionQueue.async {
                session.startRunning()
            }
        } catch {
            print("Error setting up session: \(error)")
        }
    }

    private func configureVideoConnection(for output: AVCaptureMovieFileOutput) {
        if let videoConnection = output.connection(with: .video) {
            if videoConnection.isVideoStabilizationSupported {
                videoConnection.preferredVideoStabilizationMode = .auto
            }

            videoConnection.videoOrientation = .portrait
            videoConnection.isVideoMirrored = (position == .frontWide || position == .frontTelephoto)
        }
    }

    private func configureVideoCodec(for output: AVCaptureMovieFileOutput) {
        let codecManager = VideoCodecManager.shared
        output.setOutputSettings(codecManager.getVideoSettings(), for: output.connections.first)
    }

    private func configureVideoStabilization(for output: AVCaptureMovieFileOutput) {
        if let connection = output.connection(with: .video) {
            if connection.isVideoStabilizationSupported {
                connection.preferredVideoStabilizationMode = .auto
            }
        }
    }

    private func configureFocusAndExposure(device: AVCaptureDevice) {
        do {
            try device.lockForConfiguration()

            if device.isFocusModeSupported(.continuousAutoFocus) {
                device.focusMode = .continuousAutoFocus
            }

            if device.isExposureModeSupported(.continuousAutoExposure) {
                device.exposureMode = .continuousAutoExposure
            }

            if device.isWhiteBalanceModeSupported(.continuousAutoWhiteBalance) {
                device.whiteBalanceMode = .continuousAutoWhiteBalance
            }

            device.unlockForConfiguration()
        } catch {
            print("Error configuring focus/exposure: \(error)")
        }
    }

    mutating func startRecording(to url: URL, delegate: AVCaptureFileOutputRecordingDelegate) {
        guard let videoOutput = videoOutput else {
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
        }
    }
}
