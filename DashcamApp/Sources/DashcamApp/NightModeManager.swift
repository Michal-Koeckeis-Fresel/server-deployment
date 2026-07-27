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
    @Published var isAutomatic: Bool = UserDefaults.standard.bool(forKey: "nightModeAutomatic") {
        didSet {
            UserDefaults.standard.set(isAutomatic, forKey: "nightModeAutomatic")
            if isAutomatic {
                startBrightnessMonitoring()
            } else {
                stopBrightnessMonitoring()
            }
        }
    }
    @Published var brightnessThreshold: Double = UserDefaults.standard.double(forKey: "nightModeBrightnessThreshold") {
        didSet {
            let clamped = max(-8.0, min(-2.0, brightnessThreshold))
            if clamped != brightnessThreshold {
                brightnessThreshold = clamped
            }
            UserDefaults.standard.set(brightnessThreshold, forKey: "nightModeBrightnessThreshold")
        }
    }
    @Published var useExtendedExposure: Bool = UserDefaults.standard.bool(forKey: "nightModeExtendedExposure") {
        didSet {
            UserDefaults.standard.set(useExtendedExposure, forKey: "nightModeExtendedExposure")
        }
    }
    @Published var exposureDurationMs: Double = UserDefaults.standard.double(forKey: "nightModeExposureDuration") {
        didSet {
            let clamped = max(8.33, min(33.33, exposureDurationMs))
            if clamped != exposureDurationMs {
                exposureDurationMs = clamped
            }
            UserDefaults.standard.set(exposureDurationMs, forKey: "nightModeExposureDuration")
            applyExposureSettings()
        }
    }
    @Published var isSupported: Bool = false
    @Published var isActive: Bool = false
    @Published var currentBrightness: Double = 0.0

    private var brightnessMonitorTimer: Timer?
    private var captureDevice: AVCaptureDevice?

    override init() {
        super.init()
        checkNightModeSupport()
        if UserDefaults.standard.double(forKey: "nightModeBrightnessThreshold") == 0 {
            brightnessThreshold = -5.0
        }
        if UserDefaults.standard.double(forKey: "nightModeExposureDuration") == 0 {
            exposureDurationMs = 16.67
        }
    }

    private func checkNightModeSupport() {
        isSupported = UIDevice.current.systemVersion >= "16.0"
    }

    func enableNightMode(for device: AVCaptureDevice) {
        guard (isEnabled || isAutomatic) && isSupported else { return }

        do {
            try device.lockForConfiguration()

            if device.isLowLightBoostSupported {
                device.automaticallyEnablesLowLightBoostWhenAvailable = true
                isActive = device.isLowLightBoostEnabled
                logNightMode("Night Mode enabled via Low Light Boost")
            }

            device.unlockForConfiguration()
            self.captureDevice = device

            if isAutomatic {
                startBrightnessMonitoring()
            }
        } catch {
            print("Failed to enable Night Mode: \(error.localizedDescription)")
        }
    }

    func disableNightMode(for device: AVCaptureDevice) {
        do {
            try device.lockForConfiguration()

            if device.isLowLightBoostSupported {
                device.automaticallyEnablesLowLightBoostWhenAvailable = false
            }

            device.unlockForConfiguration()
            isActive = false
            stopBrightnessMonitoring()
        } catch {
            print("Failed to disable Night Mode: \(error.localizedDescription)")
        }
    }

    func updateNightModeStatus(for device: AVCaptureDevice) {
        isActive = device.isLowLightBoostEnabled
    }

    private func startBrightnessMonitoring() {
        guard isAutomatic, brightnessMonitorTimer == nil else { return }

        brightnessMonitorTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.checkBrightnessAndToggleNightMode()
        }
    }

    private func stopBrightnessMonitoring() {
        brightnessMonitorTimer?.invalidate()
        brightnessMonitorTimer = nil
    }

    private func checkBrightnessAndToggleNightMode() {
        guard let device = captureDevice else { return }

        let exposure = device.exposureTargetBias
        currentBrightness = Double(exposure)

        do {
            try device.lockForConfiguration()

            if device.isLowLightBoostSupported {
                let shouldEnableLowLightBoost = exposure < Float(brightnessThreshold)

                if shouldEnableLowLightBoost && !device.isLowLightBoostEnabled {
                    device.automaticallyEnablesLowLightBoostWhenAvailable = true
                    isActive = true
                    applyExposureSettings()
                    logNightMode("Auto Night Mode: Scene too dark (exposure: \(String(format: "%.2f", exposure)))")
                } else if !shouldEnableLowLightBoost && device.isLowLightBoostEnabled && !isEnabled {
                    device.automaticallyEnablesLowLightBoostWhenAvailable = false
                    isActive = false
                    resetExposureSettings()
                    logNightMode("Auto Night Mode: Scene bright enough (exposure: \(String(format: "%.2f", exposure)))")
                }
            }

            device.unlockForConfiguration()
        } catch {
            print("Failed to check brightness: \(error.localizedDescription)")
        }
    }

    private func applyExposureSettings() {
        guard let device = captureDevice, useExtendedExposure else { return }

        do {
            try device.lockForConfiguration()

            if device.isExposureModeSupported(.custom) {
                let duration = CMTimeMakeWithSeconds(exposureDurationMs / 1000.0, preferredTimescale: 1000)

                if duration >= device.activeFormat.minExposureDuration &&
                   duration <= device.activeFormat.maxExposureDuration {
                    device.setExposureModeCustom(
                        duration: duration,
                        iso: AVCaptureDevice.currentISO,
                        completionHandler: nil
                    )
                    logNightMode("Extended exposure applied: \(String(format: "%.2f", exposureDurationMs)) ms")
                }
            }

            device.unlockForConfiguration()
        } catch {
            print("Failed to apply exposure settings: \(error.localizedDescription)")
        }
    }

    private func resetExposureSettings() {
        guard let device = captureDevice else { return }

        do {
            try device.lockForConfiguration()

            if device.isExposureModeSupported(.continuousAutoExposure) {
                device.exposureMode = .continuousAutoExposure
                logNightMode("Exposure reset to automatic")
            }

            device.unlockForConfiguration()
        } catch {
            print("Failed to reset exposure settings: \(error.localizedDescription)")
        }
    }

    private func logNightMode(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[NightMode] [\(timestamp)] \(message)")
    }

    func getNightModeDescription() -> String {
        guard isSupported else { return "Night Mode not supported on this device" }
        if isAutomatic {
            return "Automatically enables Night Mode when brightness falls below threshold"
        }
        return "Manually enhanced video in low light conditions using Low Light Boost technology"
    }

    deinit {
        stopBrightnessMonitoring()
    }
}
