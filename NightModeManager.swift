import Foundation
import AVFoundation
import SwiftUI

class NightModeManager: NSObject, ObservableObject {
    static let shared = NightModeManager()

    @Published var isEnabled: Bool = UserDefaults.standard.bool(forKey: "nightModeEnabled") {
        didSet {
            UserDefaults.standard.set(isEnabled, forKey: "nightModeEnabled")
        }
    }
    @Published var isSupported: Bool = false
    @Published var isActive: Bool = false

    override init() {
        super.init()
        checkNightModeSupport()
    }

    private func checkNightModeSupport() {
        isSupported = UIDevice.current.systemVersion >= "16.0"
    }

    func enableNightMode(for device: AVCaptureDevice) {
        guard isEnabled && isSupported else { return }

        do {
            try device.lockForConfiguration()

            if device.isLowLightBoostSupported {
                device.automaticallyEnablesLowLightBoost = true
                isActive = device.isLowLightBoostEnabled
                logNightMode("Night Mode enabled via Low Light Boost")
            }

            device.unlockForConfiguration()
        } catch {
            print("Failed to enable Night Mode: \(error.localizedDescription)")
        }
    }

    func disableNightMode(for device: AVCaptureDevice) {
        do {
            try device.lockForConfiguration()

            if device.isLowLightBoostSupported {
                device.automaticallyEnablesLowLightBoost = false
            }

            device.unlockForConfiguration()
            isActive = false
        } catch {
            print("Failed to disable Night Mode: \(error.localizedDescription)")
        }
    }

    func updateNightModeStatus(for device: AVCaptureDevice) {
        isActive = device.isLowLightBoostEnabled
    }

    private func logNightMode(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[NightMode] [\(timestamp)] \(message)")
    }

    func getNightModeDescription() -> String {
        guard isSupported else { return "Night Mode not supported on this device" }
        return "Automatically enhances video in low light conditions using Low Light Boost technology"
    }
}
