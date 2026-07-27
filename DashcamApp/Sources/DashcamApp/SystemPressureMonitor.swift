import AVFoundation
import SwiftUI
import AudioToolbox

enum SystemPressureLevel: String, CaseIterable {
    case nominal = "Normal"
    case elevated = "Elevated"
    case critical = "Critical"

    var description: String {
        switch self {
        case .nominal:
            return "System operating normally"
        case .elevated:
            return "Device under thermal or memory pressure"
        case .critical:
            return "Critical pressure - consider reducing quality"
        }
    }

    var icon: String {
        switch self {
        case .nominal:
            return "checkmark.circle.fill"
        case .elevated:
            return "exclamationmark.circle.fill"
        case .critical:
            return "exclamationmark.triangle.fill"
        }
    }

    var color: Color {
        switch self {
        case .nominal:
            return .green
        case .elevated:
            return .orange
        case .critical:
            return .red
        }
    }
}

class SystemPressureMonitor: NSObject, ObservableObject {
    static let shared = SystemPressureMonitor()

    @Published var pressureLevel: SystemPressureLevel = .nominal
    @Published var thermalPressure: Float = 0.0
    @Published var thermalWarningLevel: ProcessInfo.ThermalState = .nominal
    @Published var shouldReduceQuality: Bool = false
    @Published var shouldPauseRecording: Bool = false
    @Published var recommendedFrameRate: Int32 = 30

    private var captureDevices: [AVCaptureDevice] = []
    private var pressureObservers: [NSObjectProtocol] = []
    private var thermalObservers: [NSObjectProtocol] = []
    private var lastAlertedPressureLevel: SystemPressureLevel = .nominal
    private var audioPlayer: AVAudioPlayer?

    override init() {
        super.init()
        setupPressureMonitoring()
    }

    private func setupPressureMonitoring() {
        findAllCaptureDevices()
        observeSystemPressure()
        observeThermalState()
    }

    private func findAllCaptureDevices() {
        let session = AVCaptureDevice.DiscoverySession(
            deviceTypes: [.builtInWideAngleCamera, .builtInTelephotoCamera],
            mediaType: .video,
            position: .front
        )
        captureDevices = session.devices
    }

    private func observeSystemPressure() {
        for device in captureDevices {
            let observer = NotificationCenter.default.addObserver(
                forName: AVCaptureDevice.systemPressureStateDidChangeNotification,
                object: device,
                queue: .main
            ) { [weak self] _ in
                self?.updateSystemPressure()
            }
            pressureObservers.append(observer)
        }

        updateSystemPressure()
    }

    private func observeThermalState() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(thermalStateDidChange),
            name: ProcessInfo.thermalStateDidChangeNotification,
            object: nil
        )

        updateThermalState()
    }

    @objc private func thermalStateDidChange() {
        DispatchQueue.main.async {
            self.updateThermalState()
        }
    }

    private func updateThermalState() {
        thermalWarningLevel = ProcessInfo.processInfo.thermalState
        logPressureState("Thermal state: \(thermalWarningLevel.description)")

        switch thermalWarningLevel {
        case .nominal:
            break
        case .critical:
            shouldPauseRecording = true
            shouldReduceQuality = true
        case .serious:
            shouldReduceQuality = true
            shouldPauseRecording = false
        case .moderate:
            shouldReduceQuality = false
            shouldPauseRecording = false
        @unknown default:
            break
        }
    }

    private func updateSystemPressure() {
        guard let primaryDevice = captureDevices.first else {
            pressureLevel = .nominal
            recommendedFrameRate = 30
            return
        }

        let pressureState = primaryDevice.systemPressureState
        thermalPressure = Float(pressureState.level.rawValue)

        let newPressureLevel: SystemPressureLevel

        if #available(iOS 16.4, *) {
            if pressureState.pressureFactors.contains(.thermalThrott) ||
               pressureState.pressureFactors.contains(.memoryThrott) {
                newPressureLevel = .critical
            } else if pressureState.level.rawValue > 0.75 {
                newPressureLevel = .elevated
            } else {
                newPressureLevel = .nominal
            }
        } else {
            if pressureState.level.rawValue > 0.75 {
                newPressureLevel = .elevated
            } else {
                newPressureLevel = .nominal
            }
        }

        pressureLevel = newPressureLevel

        switch pressureLevel {
        case .nominal:
            shouldReduceQuality = false
            shouldPauseRecording = false
            recommendedFrameRate = 30
            if lastAlertedPressureLevel != .nominal {
                logPressureState("Pressure returned to normal")
            }
        case .elevated:
            shouldReduceQuality = true
            shouldPauseRecording = false
            recommendedFrameRate = max(15, Int32(Float(24) * (1.0 - thermalPressure)))
            if lastAlertedPressureLevel == .nominal {
                playPressureAlert()
            }
        case .critical:
            shouldReduceQuality = true
            shouldPauseRecording = true
            recommendedFrameRate = 15
            if lastAlertedPressureLevel != .critical {
                playPressureAlert()
            }
        }

        lastAlertedPressureLevel = pressureLevel
        logPressureState("Pressure level: \(pressureLevel.rawValue), Thermal: \(String(format: "%.2f", thermalPressure)), FPS: \(recommendedFrameRate)")
    }

    private func playPressureAlert() {
        do {
            try AVAudioSession.sharedInstance().setCategory(.playback, options: .defaultToSpeaker)
            try AVAudioSession.sharedInstance().setActive(true)

            guard let soundURL = Bundle.main.url(forResource: "alert", withExtension: "wav") else {
                playSystemAlert()
                return
            }

            audioPlayer = try AVAudioPlayer(contentsOf: soundURL)
            audioPlayer?.play()
        } catch {
            playSystemAlert()
        }
    }

    private func playSystemAlert() {
        AudioServicesPlaySystemSound(1007)
    }

    private func logPressureState(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[SystemPressure] [\(timestamp)] \(message)")
    }

    var pressureDescription: String {
        "\(pressureLevel.rawValue) - \(pressureLevel.description)"
    }

    var thermalStateDescription: String {
        switch thermalWarningLevel {
        case .nominal:
            return "Nominal"
        case .moderate:
            return "Moderate"
        case .serious:
            return "Serious"
        case .critical:
            return "Critical"
        @unknown default:
            return "Unknown"
        }
    }

    func getPressureHealthStatus() -> (level: String, thermal: String, frameRate: String, shouldReduceQuality: String, shouldPauseRecording: String) {
        let levelStr = pressureLevel.rawValue
        let thermalStr = thermalStateDescription
        let frameRateStr = "\(recommendedFrameRate) fps"
        let reduceStr = shouldReduceQuality ? "Yes" : "No"
        let pauseStr = shouldPauseRecording ? "Yes" : "No"

        return (levelStr, thermalStr, frameRateStr, reduceStr, pauseStr)
    }

    func printPressureDiagnostics() {
        print("\n=== System Pressure Diagnostics Report ===")
        print("Timestamp: \(ISO8601DateFormatter().string(from: Date()))")
        print("Pressure Level: \(pressureLevel.rawValue)")
        print("Pressure Description: \(pressureLevel.description)")
        print("Thermal Pressure: \(String(format: "%.2f", thermalPressure))")
        print("Thermal State: \(thermalStateDescription)")
        print("Recommended Frame Rate: \(recommendedFrameRate) fps")
        print("Should Reduce Quality: \(shouldReduceQuality)")
        print("Should Pause Recording: \(shouldPauseRecording)")
        print("Active Capture Devices: \(captureDevices.count)")
        print("==========================================\n")
    }

    deinit {
        for observer in pressureObservers {
            NotificationCenter.default.removeObserver(observer)
        }
        pressureObservers.removeAll()
        NotificationCenter.default.removeObserver(self)
    }
}

extension ProcessInfo.ThermalState {
    var description: String {
        switch self {
        case .nominal:
            return "Thermal state is normal"
        case .moderate:
            return "Thermal state is moderate"
        case .serious:
            return "Thermal state is serious"
        case .critical:
            return "Thermal state is critical"
        @unknown default:
            return "Unknown thermal state"
        }
    }
}
