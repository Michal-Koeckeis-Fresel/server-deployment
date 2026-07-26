import Foundation
import AVFoundation
import Combine

@MainActor
class CameraDashcamViewModel: NSObject, ObservableObject {
    @Published var isRecording = false
    @Published var recordingTime: String = "00:00"
    @Published var errorMessage: String?

    private var captureSession: AVCaptureSession?
    private var videoOutput: AVCaptureMovieFileOutput?
    private var displayLink: CADisplayLink?
    private var recordingStartTime: Date?
    private let audioSession = AVAudioSession.sharedInstance()

    override init() {
        super.init()
        setupAudioSession()
        requestPermissions()
    }

    private func setupAudioSession() {
        do {
            try audioSession.setCategory(
                .record,
                mode: .default,
                options: [.duckOthers, .defaultToSpeaker]
            )
            try audioSession.setActive(true, options: .notifyOthersOnDeactivation)
        } catch {
            errorMessage = "Audio session error: \(error.localizedDescription)"
        }
    }

    private func requestPermissions() {
        AVCaptureDevice.requestAccess(for: .video) { granted in
            if !granted {
                DispatchQueue.main.async {
                    self.errorMessage = "Camera permission denied"
                }
            }
        }

        AVAudioSession.sharedInstance().requestRecordPermission { granted in
            if !granted {
                DispatchQueue.main.async {
                    self.errorMessage = "Microphone permission denied"
                }
            }
        }
    }

    func setupCamera() {
        let session = AVCaptureSession()
        session.sessionPreset = .high

        guard let videoDevice = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back) else {
            errorMessage = "No camera available"
            return
        }

        guard let audioDevice = AVCaptureDevice.default(for: .audio) else {
            errorMessage = "No microphone available"
            return
        }

        do {
            let videoInput = try AVCaptureDeviceInput(device: videoDevice)
            let audioInput = try AVCaptureDeviceInput(device: audioDevice)

            if session.canAddInput(videoInput) && session.canAddInput(audioInput) {
                session.addInput(videoInput)
                session.addInput(audioInput)
            }

            let movieOutput = AVCaptureMovieFileOutput()
            if session.canAddOutput(movieOutput) {
                session.addOutput(movieOutput)
            }

            self.captureSession = session
            self.videoOutput = movieOutput

            DispatchQueue.global(qos: .userInitiated).async {
                session.startRunning()
            }
        } catch {
            errorMessage = "Setup error: \(error.localizedDescription)"
        }
    }

    func startRecording() {
        guard let videoOutput = videoOutput, captureSession?.isRunning == true else {
            errorMessage = "Camera not ready"
            return
        }

        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let fileName = "dashcam_\(DateFormatter.iso8601.string(from: Date())).mov"
        let outputURL = documentsPath.appendingPathComponent(fileName)

        if videoOutput.isRecording {
            videoOutput.stopRecording()
        }

        recordingStartTime = Date()
        startTimerUpdate()
        videoOutput.startRecording(to: outputURL, recordingDelegate: self)
        isRecording = true
        errorMessage = nil
    }

    func stopRecording() {
        guard let videoOutput = videoOutput, videoOutput.isRecording else { return }

        videoOutput.stopRecording()
        isRecording = false
        displayLink?.invalidate()
        displayLink = nil
        recordingTime = "00:00"
    }

    private func startTimerUpdate() {
        displayLink = CADisplayLink(
            target: self,
            selector: #selector(updateRecordingTime)
        )
        displayLink?.preferredFramesPerSecond = 1
        displayLink?.add(to: .main, forMode: .common)
    }

    @objc private func updateRecordingTime() {
        guard let startTime = recordingStartTime else { return }
        let elapsed = Int(Date().timeIntervalSince(startTime))
        let hours = elapsed / 3600
        let minutes = (elapsed % 3600) / 60
        let seconds = elapsed % 60

        recordingTime = String(format: "%02d:%02d:%02d", hours, minutes, seconds)
    }
}

extension CameraDashcamViewModel: AVCaptureFileOutputRecordingDelegate {
    nonisolated func fileOutput(
        _ output: AVCaptureFileOutput,
        didFinishRecordingTo outputFileURL: URL,
        from connections: [AVCaptureConnection],
        error: Error?
    ) {
        if let error = error {
            DispatchQueue.main.async {
                self.errorMessage = "Recording error: \(error.localizedDescription)"
            }
        }
    }
}

extension DateFormatter {
    static let iso8601: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy_MM_dd_HHmmss"
        return formatter
    }()
}
