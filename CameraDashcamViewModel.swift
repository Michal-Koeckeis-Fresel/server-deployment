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

    @Published var cameraStatus: [CameraPosition: String] = [:]

    private var cameras: [CameraPosition: CameraRecorder] = [:]
    private var displayLink: CADisplayLink?
    private var recordingStartTime: Date?
    private var chunkStartTime: Date?
    private var chunkURLs: [CameraPosition: URL] = [:]
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
        initializeCameras()
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

    private func initializeCameras() {
        for position in CameraPosition.allCases {
            var camera = CameraRecorder(position: position)
            if camera.setupSession() {
                cameras[position] = camera
                cameraStatus[position] = "Ready"
            } else {
                cameraStatus[position] = "Unavailable"
            }
        }
    }

    func setupCameras() {
        initializeCameras()
        errorMessage = nil
    }

    func startRecording() {
        guard !cameras.isEmpty else {
            errorMessage = "No cameras available"
            return
        }

        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]

        chunkURLs.removeAll()
        for (position, var camera) in cameras {
            guard camera.captureSession?.isRunning == true else {
                cameraStatus[position] = "Error"
                continue
            }

            let timestamp = DateFormatter.iso8601.string(from: Date())
            let fileName = "dashcam_\(timestamp)_\(position.filePrefix)_chunk_0001.mov"
            let outputURL = documentsPath.appendingPathComponent(fileName)
            chunkURLs[position] = outputURL

            camera.startRecording(to: outputURL, delegate: self)
            cameras[position] = camera
            cameraStatus[position] = "Recording"
        }

        recordingStartTime = Date()
        chunkStartTime = Date()
        currentChunkNumber = 0
        crashDetected = false
        emergencyBrakeDetected = false
        startTimerUpdate()
        setupChunkTimer()
        setupCrashDetection()
        isRecording = true
        errorMessage = nil
    }

    func stopRecording() {
        for (position, var camera) in cameras {
            camera.stopRecording()
            cameras[position] = camera
            cameraStatus[position] = camera.captureSession?.isRunning == true ? "Ready" : "Error"
        }

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
        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let timestamp = DateFormatter.iso8601.string(from: Date())

        chunkURLs.removeAll()
        currentChunkNumber += 1

        for (position, var camera) in cameras {
            guard camera.captureSession?.isRunning == true else { continue }

            if let videoOutput = camera.videoOutput, videoOutput.isRecording {
                videoOutput.stopRecording()
            }

            let fileName = "dashcam_\(timestamp)_\(position.filePrefix)_chunk_\(String(format: "%04d", currentChunkNumber)).mov"
            let outputURL = documentsPath.appendingPathComponent(fileName)
            chunkURLs[position] = outputURL

            camera.startRecording(to: outputURL, delegate: self)
            cameras[position] = camera
        }

        chunkStartTime = Date()
        checkStorageLimit()
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
            errorMessage = "⚠️ Crash Detected! Recordings protected."
        case .emergencyBrake:
            emergencyBrakeDetected = true
            errorMessage = "🛑 Emergency Brake Detected! Recordings protected."
        }

        showCrashAlert = true

        for (_, url) in chunkURLs {
            fileProtectionManager.setProtection(true, for: url)
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

    deinit {
        for (_, camera) in cameras {
            camera.cleanup()
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
