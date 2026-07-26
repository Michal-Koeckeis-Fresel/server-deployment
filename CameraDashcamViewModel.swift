import Foundation
import AVFoundation
import Combine

@MainActor
class CameraDashcamViewModel: NSObject, ObservableObject {
    @Published var isRecording = false
    @Published var recordingTime: String = "00:00"
    @Published var errorMessage: String?
    @Published var currentChunkNumber: Int = 0
    @Published var currentStorageGB: Double = 0.0
    @Published var maxStorageGB: Double = UserDefaults.standard.double(forKey: "maxStorageGB") {
        didSet {
            UserDefaults.standard.set(maxStorageGB, forKey: "maxStorageGB")
            checkStorageLimit()
        }
    }
    @Published var chunkDurationMinutes: Int = UserDefaults.standard.integer(forKey: "chunkDurationMinutes") {
        didSet {
            let clamped = max(1, min(15, chunkDurationMinutes))
            if clamped != chunkDurationMinutes {
                chunkDurationMinutes = clamped
            }
            UserDefaults.standard.set(chunkDurationMinutes, forKey: "chunkDurationMinutes")
        }
    }

    private var captureSession: AVCaptureSession?
    private var videoOutput: AVCaptureMovieFileOutput?
    private var displayLink: CADisplayLink?
    private var recordingStartTime: Date?
    private var chunkStartTime: Date?
    private var currentChunkURL: URL?
    private var chunkTimer: Timer?
    private let audioSession = AVAudioSession.sharedInstance()
    private let storageManager = StorageManager()
    private let fileProtectionManager = FileProtectionManager()
    private let crashDetectionManager = CrashDetectionManager()

    @Published var crashDetected = false
    @Published var emergencyBrakeDetected = false
    @Published var showCrashAlert = false
    @Published var impactEventType: ImpactEventType = .collision

    override init() {
        super.init()
        if UserDefaults.standard.double(forKey: "maxStorageGB") == 0 {
            maxStorageGB = 10.0
        }
        if UserDefaults.standard.integer(forKey: "chunkDurationMinutes") == 0 {
            chunkDurationMinutes = 5
        }
        setupAudioSession()
        requestPermissions()
        updateStorageInfo()
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

        if videoOutput.isRecording {
            videoOutput.stopRecording()
        }

        recordingStartTime = Date()
        chunkStartTime = Date()
        currentChunkNumber = 0
        crashDetected = false
        emergencyBrakeDetected = false
        startNewChunk()
        startTimerUpdate()
        setupChunkTimer()
        setupCrashDetection()
        isRecording = true
        errorMessage = nil
    }

    func stopRecording() {
        guard let videoOutput = videoOutput, videoOutput.isRecording else { return }

        videoOutput.stopRecording()
        isRecording = false
        displayLink?.invalidate()
        displayLink = nil
        chunkTimer?.invalidate()
        chunkTimer = nil
        crashDetectionManager.stopMonitoring()
        recordingTime = "00:00"
        updateStorageInfo()
    }

    private func startNewChunk() {
        guard let videoOutput = videoOutput, captureSession?.isRunning == true else { return }

        if videoOutput.isRecording {
            videoOutput.stopRecording()
        }

        currentChunkNumber += 1
        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let timestamp = DateFormatter.iso8601.string(from: Date())
        let fileName = "dashcam_\(timestamp)_chunk_\(String(format: "%04d", currentChunkNumber)).mov"
        let outputURL = documentsPath.appendingPathComponent(fileName)
        currentChunkURL = outputURL

        chunkStartTime = Date()
        checkStorageLimit()
        videoOutput.startRecording(to: outputURL, recordingDelegate: self)
    }

    private func setupChunkTimer() {
        chunkTimer?.invalidate()
        chunkTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.checkChunkDuration()
        }
    }

    private func checkChunkDuration() {
        guard isRecording, let chunkStart = chunkStartTime else { return }
        let elapsed = Int(Date().timeIntervalSince(chunkStart))
        let maxSeconds = chunkDurationMinutes * 60

        if elapsed >= maxSeconds {
            startNewChunk()
        }
    }

    private func checkStorageLimit() {
        Task {
            await storageManager.checkAndCleanupIfNeeded(
                maxStorageGB: maxStorageGB,
                protectionManager: fileProtectionManager
            )
            updateStorageInfo()
        }
    }

    private func updateStorageInfo() {
        let docPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        currentStorageGB = storageManager.calculateUsedStorage(at: docPath)
    }

    private func setupCrashDetection() {
        crashDetectionManager.startMonitoring { [weak self] eventType in
            DispatchQueue.main.async {
                self?.handleImpactEventDetected(eventType)
            }
        }
    }

    private func handleImpactEventDetected(_ eventType: ImpactEventType) {
        impactEventType = eventType

        switch eventType {
        case .collision:
            crashDetected = true
            errorMessage = "⚠️ Crash Detected! Current recording protected."
        case .emergencyBrake:
            emergencyBrakeDetected = true
            errorMessage = "🛑 Emergency Brake Detected! Current recording protected."
        }

        showCrashAlert = true

        if let currentChunkURL = currentChunkURL {
            fileProtectionManager.setProtection(true, for: currentChunkURL)
        }
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

    func toggleFileProtection(for url: URL) {
        fileProtectionManager.toggleProtection(for: url)
    }

    func isFileProtected(url: URL) -> Bool {
        fileProtectionManager.isProtected(url: url)
    }

    func deleteFile(at url: URL) -> Bool {
        return storageManager.deleteFile(at: url)
    }

    func getRecordedFiles() -> [URL] {
        let docPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        do {
            let files = try FileManager.default.contentsOfDirectory(
                at: docPath,
                includingPropertiesForKeys: [.contentModificationDateKey]
            ).filter { $0.pathExtension == "mov" }
            return files.sorted {
                let date1 = try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate ?? Date()
                let date2 = try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate ?? Date()
                return (date1 ?? Date()) > (date2 ?? Date())
            }
        } catch {
            errorMessage = "Failed to read files: \(error.localizedDescription)"
            return []
        }
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
        } else {
            DispatchQueue.main.async {
                self.updateStorageInfo()
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
