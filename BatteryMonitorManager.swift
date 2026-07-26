import UIKit
import AVFoundation

class BatteryMonitorManager: NSObject, ObservableObject {
    static let shared = BatteryMonitorManager()

    @Published var batteryLevel: Float = UIDevice.current.batteryLevel
    @Published var batteryState: UIDevice.BatteryState = UIDevice.current.batteryState
    @Published var isCharging: Bool = false
    @Published var showLowBatteryAlert: Bool = false

    private var lastAlertBatteryLevel: Float = 0.0
    private let lowBatteryThreshold: Float = 0.20
    private let criticalBatteryThreshold: Float = 0.10
    private var audioPlayer: AVAudioPlayer?

    override init() {
        super.init()
        setupBatteryMonitoring()
    }

    private func setupBatteryMonitoring() {
        UIDevice.current.isBatteryMonitoringEnabled = true

        batteryLevel = UIDevice.current.batteryLevel
        batteryState = UIDevice.current.batteryState
        isCharging = UIDevice.current.batteryState == .charging || UIDevice.current.batteryState == .full

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

    @objc private func batteryLevelDidChange() {
        DispatchQueue.main.async {
            self.batteryLevel = UIDevice.current.batteryLevel
            self.checkBatteryStatus()
        }
    }

    @objc private func batteryStateDidChange() {
        DispatchQueue.main.async {
            self.batteryState = UIDevice.current.batteryState
            self.isCharging = UIDevice.current.batteryState == .charging || UIDevice.current.batteryState == .full
            self.checkBatteryStatus()
        }
    }

    private func checkBatteryStatus() {
        let currentBatteryLevel = batteryLevel

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

    var batteryPercentage: String {
        String(format: "%.0f%%", batteryLevel * 100)
    }

    var batteryStatusDescription: String {
        if isCharging {
            return "🔌 Charging"
        } else if batteryLevel < criticalBatteryThreshold {
            return "🔴 Critical (<10%)"
        } else if batteryLevel < lowBatteryThreshold {
            return "🟠 Low (<20%)"
        } else if batteryLevel < 0.5 {
            return "🟡 Moderate"
        } else {
            return "🟢 Good"
        }
    }

    var shouldShowLowBatteryWarning: Bool {
        !isCharging && batteryLevel < lowBatteryThreshold
    }

    var shouldStopRecording: Bool {
        !isCharging && batteryLevel < criticalBatteryThreshold
    }

    func getBatteryHealthStatus() -> (level: String, state: String, charging: String) {
        let levelStr = String(format: "%.1f%%", batteryLevel * 100)
        let stateStr = {
            switch batteryState {
            case .charging:
                return "Charging"
            case .full:
                return "Full"
            case .unplugged:
                return "Unplugged"
            @unknown default:
                return "Unknown"
            }
        }()

        let chargingStr = isCharging ? "Yes" : "No"

        return (levelStr, stateStr, chargingStr)
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
        UIDevice.current.isBatteryMonitoringEnabled = false
    }
}
