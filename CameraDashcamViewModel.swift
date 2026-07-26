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
    @Published var reservedSystemSpaceGB: Double = UserDefaults.standard.double(forKey: "reservedSystemSpaceGB") {
        didSet {
            let clamped = max(1.0, min(50.0, reservedSystemSpaceGB))
            if clamped != reservedSystemSpaceGB {
                reservedSystemSpaceGB = clamped
            }
            UserDefaults.standard.set(reservedSystemSpaceGB, forKey: "reservedSystemSpaceGB")
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
    private let storageLocationManager = StorageLocationManager.shared
    private let systemPressureMonitor = SystemPressureMonitor.shared
    private let lowPowerModeMonitor = LowPowerModeMonitor.shared
    private let locationManager = LocationManager.shared
    private let parkingModeManager = ParkingModeManager.shared
    private let autoStartManager = AutoStartRecordingManager.shared
    private let gForceMonitor = GForceMonitor.shared
    private let performanceLogger = PerformanceLogger.shared
    private let audioEventDetector = AudioEventDetector.shared
    @available(iOS 14.0, *)
    private let watchConnectivityManager = WatchConnectivityManager.shared

    @Published var crashDetected = false
    @Published var emergencyBrakeDetected = false
    @Published var showCrashAlert = false
    @Published var impactEventType: ImpactEventType = .collision
    @Published var thermalWarningMessage: String?
    @Published var isSlowMotionActive: Bool = false

    @Published var fpsCounter = FPSCounter()

    private var slowMotionTimer: Timer?
    private let slowMotionDuration: TimeInterval = 3.0

    override init() {
        super.init()
        if UserDefaults.standard.double(forKey: "maxStorageGB") == 0 {
            maxStorageGB = 10.0
        }
        if UserDefaults.standard.double(forKey: "reservedSystemSpaceGB") == 0 {
            reservedSystemSpaceGB = 5.0
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

        if storageLocationManager.selectedLocation == .photos {
            storageLocationManager.requestPhotosPermission { _ in }
        }
    }

    private func initializeCameras() {
        let capabilityChecker = CameraCapabilityChecker.shared
        capabilityChecker.printCapabilitiesReport()

        for position in CameraPosition.allCases {
            let capabilities = capabilityChecker.checkCapabilities(for: position)

            if !capabilities.isAvailable {
                cameraStatus[position] = "Unavailable"
                continue
            }

            var camera = CameraRecorder(position: position)
            if camera.setupSession() {
                cameras[position] = camera
                cameraStatus[position] = camera.getSessionStatus()
            } else {
                cameraStatus[position] = "Setup Failed"
            }
        }
    }

    func setupCameras() {
        initializeCameras()
        errorMessage = nil
        updateCameraStatus()
    }

    private func updateCameraStatus() {
        for (position, camera) in cameras {
            let status = camera.getSessionStatus()
            cameraStatus[position] = status
            if status == "Setup Failed" {
                errorMessage = "Camera setup issue for \(position.rawValue). Try restarting the app."
            }
        }
    }

    func recoverCameraSession() {
        for (position, camera) in cameras {
            var mutableCamera = camera
            if mutableCamera.captureSession?.isRunning == false {
                if mutableCamera.setupSession() {
                    cameras[position] = mutableCamera
                    cameraStatus[position] = "Ready"
                } else {
                    cameraStatus[position] = "Recovery Failed"
                }
            }
            cameras[position] = mutableCamera
        }
    }

    func startRecording() {
        guard !cameras.isEmpty else {
            errorMessage = "No cameras available"
            return
        }

        if systemPressureMonitor.shouldPauseRecording {
            errorMessage = "⚠️ Device under critical thermal load. Pause recording and let device cool down."
            thermalWarningMessage = "Critical thermal pressure detected"
            return
        }

        if systemPressureMonitor.shouldReduceQuality {
            thermalWarningMessage = "Device under thermal pressure - video quality reduced"
        } else if lowPowerModeMonitor.isLowPowerModeEnabled {
            thermalWarningMessage = "Low Power Mode active - video quality reduced to save battery"
        }

        if autoStartManager.shouldAutoStartRecording() {
            print("Auto-start recording triggered: driving detected")
        }

        guard let recordingsPath = storageLocationManager.getRecordingsURL() else {
            errorMessage = "Storage location not available. Check settings."
            return
        }

        chunkURLs.removeAll()
        for (position, var camera) in cameras {
            guard camera.captureSession?.isRunning == true else {
                cameraStatus[position] = "Error"
                continue
            }

            let timestamp = DateFormatter.iso8601.string(from: Date())
            let fileName = "dashcam_\(timestamp)_\(position.filePrefix)_chunk_0001.mov"
            let outputURL = recordingsPath.appendingPathComponent(fileName)
            chunkURLs[position] = outputURL

            let watermarkGenerator = WatermarkTextGenerator(
                fpsCounter: fpsCounter,
                batteryManager: BatteryMonitorManager.shared,
                locationManager: locationManager
            )
            camera.startRecording(to: outputURL, delegate: self, withWatermark: watermarkGenerator)
            cameras[position] = camera
            cameraStatus[position] = "Recording"
        }

        recordingStartTime = Date()
        chunkStartTime = Date()
        currentChunkNumber = 0
        crashDetected = false
        emergencyBrakeDetected = false
        fpsCounter.start()
        gForceMonitor.startMonitoring()
        performanceLogger.startRecording()
        audioEventDetector.startMonitoring()
        locationManager.startLocationUpdates()
        startTimerUpdate()
        setupChunkTimer()
        setupCrashDetection()

        if #available(iOS 14.0, *) {
            watchConnectivityManager.sendRecordingStatusAlert(isRecording: true)
        }

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
        fpsCounter.stop()
        fpsCounter.printFPSReport()
        gForceMonitor.stopMonitoring()
        performanceLogger.stopRecording()
        audioEventDetector.stopMonitoring()
        locationManager.stopLocationUpdates()

        if #available(iOS 14.0, *) {
            watchConnectivityManager.sendRecordingStatusAlert(isRecording: false)
        }
        displayLink?.invalidate()
        displayLink = nil
        chunkTimer?.invalidate()
        chunkTimer = nil
        slowMotionTimer?.invalidate()
        slowMotionTimer = nil
        crashDetectionManager.stopMonitoring()
        recordingTime = "00:00"
        thermalWarningMessage = nil
        isSlowMotionActive = false
        updateStorageInfo()
    }

    private func checkThermalPressure() {
        if systemPressureMonitor.shouldPauseRecording && isRecording {
            stopRecording()
            thermalWarningMessage = "Critical thermal pressure - recording paused automatically"
            errorMessage = "🌡️ Device cooling required. Recording paused."
        } else if (systemPressureMonitor.shouldReduceQuality || lowPowerModeMonitor.shouldReduceQuality) && isRecording {
            let reason = systemPressureMonitor.shouldReduceQuality ? "thermal pressure" : "Low Power Mode"
            if thermalWarningMessage == nil {
                thermalWarningMessage = "Device under \(reason) - video quality and frame rate reduced"
            }
            adjustFrameRates()
        } else if thermalWarningMessage != nil && !systemPressureMonitor.shouldReduceQuality && !lowPowerModeMonitor.shouldReduceQuality {
            thermalWarningMessage = nil
            restoreFrameRates()
        }
    }

    private func adjustFrameRates() {
        let thermalFPS = systemPressureMonitor.recommendedFrameRate
        let powerModeFPS = lowPowerModeMonitor.recommendedFrameRate
        let effectiveFPS = min(thermalFPS, powerModeFPS)

        for position in cameras.keys {
            var camera = cameras[position]!
            camera.setFrameRate(effectiveFPS)
            cameras[position] = camera
        }
    }

    private func restoreFrameRates() {
        for position in cameras.keys {
            var camera = cameras[position]!
            camera.setFrameRate(30)
            cameras[position] = camera
        }
    }

    private func startNewChunk() {
        guard let recordingsPath = storageLocationManager.getRecordingsURL() else {
            return
        }

        let timestamp = DateFormatter.iso8601.string(from: Date())

        chunkURLs.removeAll()
        currentChunkNumber += 1

        for (position, var camera) in cameras {
            guard camera.captureSession?.isRunning == true else { continue }

            if let videoOutput = camera.videoOutput, videoOutput.isRecording {
                videoOutput.stopRecording()
            }

            let fileName = "dashcam_\(timestamp)_\(position.filePrefix)_chunk_\(String(format: "%04d", currentChunkNumber)).mov"
            let outputURL = recordingsPath.appendingPathComponent(fileName)
            chunkURLs[position] = outputURL

            let watermarkGenerator = WatermarkTextGenerator(
                fpsCounter: fpsCounter,
                batteryManager: BatteryMonitorManager.shared,
                locationManager: locationManager
            )
            camera.startRecording(to: outputURL, delegate: self, withWatermark: watermarkGenerator)
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

        checkThermalPressure()

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
                reservedSpaceGB: reservedSystemSpaceGB,
                protectionManager: fileProtectionManager
            )
            updateStorageInfo()
        }
    }

    private func updateStorageInfo() {
        guard let recordingsPath = storageLocationManager.getRecordingsURL() else {
            currentStorageGB = 0.0
            return
        }
        currentStorageGB = storageManager.calculateUsedStorage(at: recordingsPath)
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

        performanceLogger.recordFrame()
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
            if #available(iOS 14.0, *) {
                watchConnectivityManager.sendCrashAlert(type: "Collision")
            }
        case .emergencyBrake:
            emergencyBrakeDetected = true
            errorMessage = "🛑 Emergency Brake Detected! Recordings protected."
            if #available(iOS 14.0, *) {
                watchConnectivityManager.sendEmergencyBrakeAlert()
            }
        }

        showCrashAlert = true
        activateSlowMotion()

        for (_, url) in chunkURLs {
            fileProtectionManager.setProtection(true, for: url)
        }
    }

    private func activateSlowMotion() {
        isSlowMotionActive = true

        for position in cameras.keys {
            var camera = cameras[position]!
            camera.setSlowMotionFrameRate(60)
            cameras[position] = camera
        }

        slowMotionTimer?.invalidate()
        slowMotionTimer = Timer.scheduledTimer(withTimeInterval: slowMotionDuration, repeats: false) { [weak self] _ in
            self?.deactivateSlowMotion()
        }

        logImpactEvent("Slow-motion activated at 60 fps")
    }

    private func deactivateSlowMotion() {
        isSlowMotionActive = false
        slowMotionTimer?.invalidate()
        slowMotionTimer = nil

        adjustFrameRates()
        logImpactEvent("Slow-motion deactivated, returning to normal frame rate")
    }

    private func logImpactEvent(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[Impact] [\(timestamp)] \(message)")
    }

    func toggleFileProtection(for url: URL) {
        fileProtectionManager.toggleProtection(for: url)
    }

    func isFileProtected(url: URL) -> Bool {
        fileProtectionManager.isProtected(url: url)
    }

    func protectCurrentChunk() {
        for (_, url) in chunkURLs {
            fileProtectionManager.setProtection(true, for: url)
        }
        errorMessage = "✅ Current recording protected from deletion"
        DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
            self.errorMessage = nil
        }
    }

    func deleteFile(at url: URL) -> Bool {
        return storageManager.deleteFile(at: url)
    }

    func getRecordedFiles() -> [URL] {
        guard let recordingsPath = storageLocationManager.getRecordingsURL() else {
            errorMessage = "Storage location not available"
            return []
        }

        do {
            let files = try FileManager.default.contentsOfDirectory(
                at: recordingsPath,
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

                if self.storageLocationManager.selectedLocation == .photos {
                    self.storageLocationManager.saveVideoToPhotos(outputFileURL) { success in
                        DispatchQueue.main.async {
                            if success {
                                print("Video saved to Photos: \(outputFileURL.lastPathComponent)")
                            }
                        }
                    }
                }
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
