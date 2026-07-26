import Foundation
import SwiftUI

class LowPowerModeMonitor: NSObject, ObservableObject {
    static let shared = LowPowerModeMonitor()

    @Published var isLowPowerModeEnabled: Bool = false
    @Published var recommendedFrameRate: Int32 = 30
    @Published var shouldReduceQuality: Bool = false

    override init() {
        super.init()
        setupLowPowerModeMonitoring()
    }

    private func setupLowPowerModeMonitoring() {
        updateLowPowerState()

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(powerStateDidChange),
            name: NSProcessInfo.powerStateDidChangeNotification,
            object: nil
        )
    }

    @objc private func powerStateDidChange() {
        DispatchQueue.main.async {
            self.updateLowPowerState()
        }
    }

    private func updateLowPowerState() {
        let previousState = isLowPowerModeEnabled
        isLowPowerModeEnabled = ProcessInfo.processInfo.isLowPowerModeEnabled

        if isLowPowerModeEnabled {
            recommendedFrameRate = 24
            shouldReduceQuality = true
            if !previousState {
                logPowerState("Low Power Mode enabled - reducing frame rate to 24 fps and quality")
            }
        } else {
            recommendedFrameRate = 30
            shouldReduceQuality = false
            if previousState {
                logPowerState("Low Power Mode disabled - restoring normal settings")
            }
        }
    }

    private func logPowerState(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[LowPowerMode] [\(timestamp)] \(message)")
    }

    var powerStateDescription: String {
        isLowPowerModeEnabled ? "Enabled" : "Disabled"
    }

    var statusMessage: String {
        isLowPowerModeEnabled ? "Low Power Mode active - frame rate reduced to 24 fps" : "Normal operation"
    }

    func getPowerModeStatus() -> (enabled: String, frameRate: String, quality: String) {
        let enabledStr = isLowPowerModeEnabled ? "Yes" : "No"
        let frameRateStr = "\(recommendedFrameRate) fps"
        let qualityStr = shouldReduceQuality ? "Reduced" : "Full"

        return (enabledStr, frameRateStr, qualityStr)
    }

    func printPowerModeDiagnostics() {
        print("\n=== Low Power Mode Diagnostics Report ===")
        print("Timestamp: \(ISO8601DateFormatter().string(from: Date()))")
        print("Low Power Mode Enabled: \(isLowPowerModeEnabled)")
        print("Recommended Frame Rate: \(recommendedFrameRate) fps")
        print("Should Reduce Quality: \(shouldReduceQuality)")
        print("=========================================\n")
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
}
