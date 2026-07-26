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
    var isRecording: Bool = false
    var currentURL: URL?

    mutating func setupSession() -> Bool {
        let session = AVCaptureSession()
        session.sessionPreset = .high

        guard let videoDevice = AVCaptureDevice.default(
            position.deviceType,
            for: .video,
            position: position.position
        ) else {
            return false
        }

        do {
            let videoInput = try AVCaptureDeviceInput(device: videoDevice)

            if session.canAddInput(videoInput) {
                session.addInput(videoInput)
            } else {
                return false
            }

            let movieOutput = AVCaptureMovieFileOutput()
            if session.canAddOutput(movieOutput) {
                session.addOutput(movieOutput)
            } else {
                return false
            }

            self.captureSession = session
            self.videoOutput = movieOutput

            DispatchQueue.global(qos: .userInitiated).async {
                session.startRunning()
            }

            return true
        } catch {
            return false
        }
    }

    mutating func startRecording(to url: URL, delegate: AVCaptureFileOutputRecordingDelegate) {
        guard let videoOutput = videoOutput, captureSession?.isRunning == true else {
            return
        }

        if videoOutput.isRecording {
            videoOutput.stopRecording()
        }

        currentURL = url
        videoOutput.startRecording(to: url, recordingDelegate: delegate)
        isRecording = true
    }

    mutating func stopRecording() {
        guard let videoOutput = videoOutput, videoOutput.isRecording else {
            return
        }

        videoOutput.stopRecording()
        isRecording = false
    }

    func cleanup() {
        if let session = captureSession, session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async {
                session.stopRunning()
            }
        }
    }
}
