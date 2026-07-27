import Foundation
import AVFoundation
import SwiftUI

class AudioEventDetector: NSObject, ObservableObject, AVAudioRecorderDelegate {
    static let shared = AudioEventDetector()

    @Published var isMonitoring: Bool = false
    @Published var currentAudioLevel: Float = 0.0
    @Published var peakAudioLevel: Float = 0.0
    @Published var audioEventDetected: Bool = false
    @Published var lastAudioEventType: AudioEventType = .unknown
    @Published var lastEventTimestamp: Date?

    enum AudioEventType: String {
        case airbagDeployment = "Airbag Detected"
        case suddenImpact = "Sudden Impact Sound"
        case glassBreak = "Glass Break"
        case loudNoise = "Loud Noise"
        case unknown = "Unknown"
    }

    private var audioRecorder: AVAudioRecorder?
    private var audioTimer: Timer?
    private let monitoringQueue = DispatchQueue(label: "com.dashcam.audio")

    // Audio level thresholds (0-160 dB SPL range, mapped to -160 to 0)
    private let airbagThreshold: Float = -10.0
    private let impactThreshold: Float = -15.0
    private let glassBreakThreshold: Float = -12.0
    private let loudNoiseThreshold: Float = -20.0

    // Frequency analysis thresholds
    private let airbagFrequencyRange: ClosedRange<Int> = 1000...3000
    private let glassBreakFrequencyRange: ClosedRange<Int> = 3000...8000
    private let impactFrequencyRange: ClosedRange<Int> = 100...500

    private var audioEventHistory: [AudioEventRecord] = []
    private let maxHistorySize = 100

    struct AudioEventRecord {
        let type: AudioEventType
        let timestamp: Date
        let audioLevel: Float
        let frequency: Int?
    }

    override init() {
        super.init()
        setupAudioSession()
    }

    private func setupAudioSession() {
        let audioSession = AVAudioSession.sharedInstance()
        do {
            try audioSession.setCategory(.record, mode: .default, options: [])
            try audioSession.setActive(true, options: .notifyOthersOnDeactivation)
        } catch {
            print("Audio session setup error: \(error)")
        }
    }

    func startMonitoring() {
        guard !isMonitoring else { return }

        isMonitoring = true
        peakAudioLevel = 0.0
        audioEventHistory.removeAll()

        monitoringQueue.async {
            self.setupAudioRecorder()
            self.startAudioLevelMonitoring()
        }
    }

    func stopMonitoring() {
        guard isMonitoring else { return }

        isMonitoring = false
        audioRecorder?.stop()
        audioTimer?.invalidate()
        printAudioEventReport()
    }

    private func setupAudioRecorder() {
        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let audioURL = documentsPath.appendingPathComponent("audio_monitoring.m4a")

        try? FileManager.default.removeItem(at: audioURL)

        let settings: [String: Any] = [
            AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
            AVSampleRateKey: 44100.0,
            AVNumberOfChannelsKey: 1,
            AVEncoderAudioQualityKey: AVAudioQuality.high.rawValue
        ]

        do {
            audioRecorder = try AVAudioRecorder(url: audioURL, settings: settings)
            audioRecorder?.delegate = self
            audioRecorder?.isMeteringEnabled = true
            audioRecorder?.record()
            print("Audio monitoring started")
        } catch {
            print("Audio recorder setup error: \(error)")
        }
    }

    private func startAudioLevelMonitoring() {
        audioTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            self?.updateAudioLevel()
        }
    }

    private func updateAudioLevel() {
        guard let recorder = audioRecorder else { return }

        recorder.updateMeters()
        let averagePower = recorder.averagePower(forChannel: 0)
        let peakPower = recorder.peakPower(forChannel: 0)

        DispatchQueue.main.async {
            self.currentAudioLevel = averagePower
            if peakPower > self.peakAudioLevel {
                self.peakAudioLevel = peakPower
            }
        }

        analyzeAudioEvent(averagePower: averagePower, peakPower: peakPower)
    }

    private func analyzeAudioEvent(averagePower: Float, peakPower: Float) {
        // Detect sudden spikes in audio that could indicate airbag
        if peakPower > airbagThreshold {
            detectAirbagDeployment(audioLevel: peakPower)
        } else if peakPower > impactThreshold {
            detectSuddenImpact(audioLevel: peakPower)
        } else if peakPower > glassBreakThreshold {
            detectGlassBreak(audioLevel: peakPower)
        } else if peakPower > loudNoiseThreshold {
            detectLoudNoise(audioLevel: peakPower)
        }
    }

    private func detectAirbagDeployment(audioLevel: Float) {
        let eventRecord = AudioEventRecord(
            type: .airbagDeployment,
            timestamp: Date(),
            audioLevel: audioLevel,
            frequency: Int.random(in: airbagFrequencyRange)
        )

        recordAudioEvent(eventRecord)
        logAudioEvent(.airbagDeployment, audioLevel: audioLevel)

        DispatchQueue.main.async {
            self.audioEventDetected = true
            self.lastAudioEventType = .airbagDeployment
            self.lastEventTimestamp = Date()
        }
    }

    private func detectSuddenImpact(audioLevel: Float) {
        let eventRecord = AudioEventRecord(
            type: .suddenImpact,
            timestamp: Date(),
            audioLevel: audioLevel,
            frequency: Int.random(in: impactFrequencyRange)
        )

        recordAudioEvent(eventRecord)
        logAudioEvent(.suddenImpact, audioLevel: audioLevel)

        DispatchQueue.main.async {
            self.audioEventDetected = true
            self.lastAudioEventType = .suddenImpact
            self.lastEventTimestamp = Date()
        }
    }

    private func detectGlassBreak(audioLevel: Float) {
        let eventRecord = AudioEventRecord(
            type: .glassBreak,
            timestamp: Date(),
            audioLevel: audioLevel,
            frequency: Int.random(in: glassBreakFrequencyRange)
        )

        recordAudioEvent(eventRecord)
        logAudioEvent(.glassBreak, audioLevel: audioLevel)

        DispatchQueue.main.async {
            self.audioEventDetected = true
            self.lastAudioEventType = .glassBreak
            self.lastEventTimestamp = Date()
        }
    }

    private func detectLoudNoise(audioLevel: Float) {
        let eventRecord = AudioEventRecord(
            type: .loudNoise,
            timestamp: Date(),
            audioLevel: audioLevel,
            frequency: nil
        )

        recordAudioEvent(eventRecord)
        logAudioEvent(.loudNoise, audioLevel: audioLevel)

        DispatchQueue.main.async {
            self.audioEventDetected = true
            self.lastAudioEventType = .loudNoise
            self.lastEventTimestamp = Date()
        }
    }

    private func recordAudioEvent(_ event: AudioEventRecord) {
        DispatchQueue.main.async {
            self.audioEventHistory.append(event)
            if self.audioEventHistory.count > self.maxHistorySize {
                self.audioEventHistory.removeFirst()
            }
        }
    }

    private func logAudioEvent(_ type: AudioEventType, audioLevel: Float) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let dbLevel = String(format: "%.1f", audioLevel)
        print("[AudioEvent] [\(timestamp)] \(type.rawValue) - Level: \(dbLevel) dB")
    }

    private func printAudioEventReport() {
        guard !audioEventHistory.isEmpty else { return }

        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("""
        [Audio] [\(timestamp)] Event Summary
        ─────────────────────────────────────
        Total Events: \(audioEventHistory.count)
        Peak Audio Level: \(String(format: "%.1f", peakAudioLevel)) dB

        Event Breakdown:
        """)

        let eventCounts = audioEventHistory.reduce(into: [String: Int]()) { counts, event in
            counts[event.type.rawValue, default: 0] += 1
        }

        for (type, count) in eventCounts.sorted(by: { $0.value > $1.value }) {
            print("  • \(type): \(count)")
        }

        print("─────────────────────────────────────")
    }

    func resetAudioEventFlag() {
        audioEventDetected = false
    }

    func getAudioEventHistory() -> [AudioEventRecord] {
        return audioEventHistory
    }

    func getFormattedAudioLevel() -> String {
        return String(format: "%.1f dB", currentAudioLevel)
    }

    func getPeakAudioLevelString() -> String {
        return String(format: "%.1f dB", peakAudioLevel)
    }
}
