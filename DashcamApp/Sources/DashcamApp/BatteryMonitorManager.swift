import UIKit
import AVFoundation
import AudioToolbox

enum BatteryStateDetail: String {
    case unknown = "Unknown"
    case unplugged = "Unplugged"
    case charging = "Charging"
    case full = "Full"

    var description: String {
        switch self {
        case .unknown:
            return "Battery state unknown - assuming unplugged"
        case .unplugged:
            return "Running on battery power"
        case .charging:
            return "Charging from power source"
        case .full:
            return "Fully charged and plugged in"
        }
    }

    var icon: String {
        switch self {
        case .unknown:
            return "questionmark.battery"
        case .unplugged:
            return "battery.0percent"
        case .charging:
            return "battery.100.bolt"
        case .full:
            return "battery.100"
        }
    }

    init(from state: UIDevice.BatteryState) {
        switch state {
        case .unknown:
            self = .unknown
        case .unplugged:
            self = .unplugged
        case .charging:
            self = .charging
        case .full:
            self = .full
        @unknown default:
            self = .unknown
        }
    }
}

@MainActor
final class BatteryMonitorManager: NSObject, ObservableObject {
    static let shared = BatteryMonitorManager()

    @Published var batteryLevel: Float = UIDevice.current.batteryLevel
    @Published var batteryState: UIDevice.BatteryState = UIDevice.current.batteryState
    @Published var batteryStateDetail: BatteryStateDetail = .unknown
    @Published var isCharging: Bool = false
    @Published var isFull: Bool = false
    @Published var showLowBatteryAlert: Bool = false

    private var lastAlertBatteryLevel: Float = 0.0
    private var lastBatteryState: UIDevice.BatteryState?
    private var stateTransitionCount: Int = 0
    private let lowBatteryThreshold: Float = 0.20
    private let criticalBatteryThreshold: Float = 0.10
    private var audioPlayer: AVAudioPlayer?

    override init() {
        super.init()
        setupBatteryMonitoring()
    }

    private func setupBatteryMonitoring() {
        UIDevice.current.isBatteryMonitoringEnabled = true

        updateBatteryState()
        logBatteryState("Initial state")

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(batteryLevelDidChange),
            name: UIDevice.batteryLevelDidChangeNotification,
            object: nil
        )

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(batteryStateDidChange),
            name: UIDevice.batteryStateDidChangeNotification,
            object: nil
        )
    }

    private func updateBatteryState() {
        batteryLevel = UIDevice.current.batteryLevel
        batteryState = UIDevice.current.batteryState
        batteryStateDetail = BatteryStateDetail(from: batteryState)

        switch batteryState {
        case .charging:
            isCharging = true
            isFull = false
        case .full:
            isCharging = true
            isFull = true
        case .unplugged:
            isCharging = false
            isFull = false
        case .unknown:
            isCharging = false
            isFull = false
            logBatteryState("Warning: Unknown battery state detected")
        @unknown default:
            isCharging = false
            isFull = false
            logBatteryState("Warning: Unexpected battery state")
        }
    }

    @objc private func batteryLevelDidChange() {
        DispatchQueue.main.async {
            let previousLevel = self.batteryLevel
            self.batteryLevel = UIDevice.current.batteryLevel

            if abs(self.batteryLevel - previousLevel) > 0.02 {
                self.logBatteryState("Battery level changed: \(String(format: "%.1f%%", previousLevel * 100)) → \(String(format: "%.1f%%", self.batteryLevel * 100))")
            }

            self.checkBatteryStatus()
        }
    }

    @objc private func batteryStateDidChange() {
        DispatchQueue.main.async {
            let previousState = self.batteryState
            self.updateBatteryState()

            if previousState != self.batteryState {
                self.stateTransitionCount += 1
                self.handleStateTransition(from: previousState, to: self.batteryState)
                self.logBatteryState("State transition #\(self.stateTransitionCount): \(BatteryStateDetail(from: previousState).rawValue) → \(self.batteryStateDetail.rawValue)")
            }

            self.checkBatteryStatus()
        }
    }

    private func handleStateTransition(from previousState: UIDevice.BatteryState, to newState: UIDevice.BatteryState) {
        switch (previousState, newState) {
        case (.unplugged, .charging):
            logBatteryState("Charging started")
            lastAlertBatteryLevel = 0
            showLowBatteryAlert = false

        case (.charging, .full):
            logBatteryState("Battery fully charged")
            lastAlertBatteryLevel = 0
            showLowBatteryAlert = false

        case (.charging, .unplugged), (.full, .unplugged):
            logBatteryState("Charging disconnected - running on battery")
            checkBatteryStatus()

        case (.unknown, .unplugged), (.unknown, .charging), (.unknown, .full):
            logBatteryState("Battery state resolved from unknown to \(BatteryStateDetail(from: newState).rawValue)")

        case (_, .unknown):
            logBatteryState("Warning: Battery state changed to unknown")

        default:
            break
        }
    }

    private func checkBatteryStatus() {
        let currentBatteryLevel = batteryLevel

        if batteryState == .unknown {
            logBatteryState("Skipping battery check due to unknown state")
            return
        }

        if !isCharging && currentBatteryLevel < lowBatteryThreshold {
            if currentBatteryLevel < lastAlertBatteryLevel - 0.05 || lastAlertBatteryLevel == 0 {
                triggerLowBatteryAlert()
                lastAlertBatteryLevel = currentBatteryLevel
            }
        } else if isCharging {
            lastAlertBatteryLevel = 0
            showLowBatteryAlert = false
        }
    }

    private func triggerLowBatteryAlert() {
        logBatteryState("Low battery alert triggered at \(batteryPercentage)")
        playLowBatteryBeep()
        showLowBatteryAlert = true

        DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) {
            self.showLowBatteryAlert = false
        }
    }

    private func playLowBatteryBeep() {
        do {
            try AVAudioSession.sharedInstance().setCategory(.playback, options: .defaultToSpeaker)
            try AVAudioSession.sharedInstance().setActive(true)

            guard let soundURL = Bundle.main.url(forResource: "beep", withExtension: "wav") else {
                playSystemBeep()
                return
            }

            audioPlayer = try AVAudioPlayer(contentsOf: soundURL)
            audioPlayer?.numberOfLoops = 2
            audioPlayer?.play()
        } catch {
            playSystemBeep()
        }
    }

    private func playSystemBeep() {
        AudioServicesPlaySystemSound(1011)
    }

    private func logBatteryState(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[Battery] [\(timestamp)] \(message)")
    }

    var batteryPercentage: String {
        String(format: "%.0f%%", batteryLevel * 100)
    }

    var batteryPercentageDetailed: String {
        String(format: "%.1f%%", batteryLevel * 100)
    }

    var batteryStatusDescription: String {
        switch batteryState {
        case .full:
            return "🟢 Fully Charged"
        case .charging:
            return "🔌 Charging (\(batteryPercentage))"
        case .unplugged:
            if batteryLevel < criticalBatteryThreshold {
                return "🔴 Critical (<10%)"
            } else if batteryLevel < lowBatteryThreshold {
                return "🟠 Low (<20%)"
            } else if batteryLevel < 0.5 {
                return "🟡 Moderate"
            } else {
                return "🟢 Good"
            }
        case .unknown:
            return "❓ Unknown State"
        @unknown default:
            return "❓ Unexpected State"
        }
    }

    var shouldShowLowBatteryWarning: Bool {
        !isCharging && batteryLevel < lowBatteryThreshold && batteryState != .unknown
    }

    var shouldStopRecording: Bool {
        !isCharging && batteryLevel < criticalBatteryThreshold && batteryState != .unknown
    }

    func getBatteryHealthStatus() -> (level: String, state: String, stateDetail: String, charging: String, full: String, transitions: String) {
        let levelStr = String(format: "%.1f%%", batteryLevel * 100)
        let stateStr = batteryStateDetail.rawValue
        let stateDetailStr = batteryStateDetail.description
        let chargingStr = isCharging ? "Yes" : "No"
        let fullStr = isFull ? "Yes" : "No"
        let transitionsStr = "\(stateTransitionCount)"

        return (levelStr, stateStr, stateDetailStr, chargingStr, fullStr, transitionsStr)
    }

    func printBatteryDiagnostics() {
        print("\n=== Battery Diagnostics Report ===")
        print("Timestamp: \(ISO8601DateFormatter().string(from: Date()))")
        print("Battery Level: \(batteryPercentageDetailed)")
        print("Battery State: \(batteryStateDetail.rawValue)")
        print("State Description: \(batteryStateDetail.description)")
        print("Is Charging: \(isCharging)")
        print("Is Full: \(isFull)")
        print("Status: \(batteryStatusDescription)")
        print("Low Battery Warning: \(shouldShowLowBatteryWarning)")
        print("Critical Battery: \(shouldStopRecording)")
        print("State Transitions: \(stateTransitionCount)")
        print("Monitoring Enabled: \(UIDevice.current.isBatteryMonitoringEnabled)")
        print("====================================\n")
    }

    @MainActor deinit {
        NotificationCenter.default.removeObserver(self)
        UIDevice.current.isBatteryMonitoringEnabled = false
    }
}
