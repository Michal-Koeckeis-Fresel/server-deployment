import Foundation
import CoreLocation
import SwiftUI

@MainActor
final class AutoStartRecordingManager: NSObject, ObservableObject {
    static let shared = AutoStartRecordingManager()

    @Published var isAutoStartEnabled: Bool = UserDefaults.standard.bool(forKey: "autoStartEnabled") {
        didSet {
            UserDefaults.standard.set(isAutoStartEnabled, forKey: "autoStartEnabled")
        }
    }

    @Published var isDriving: Bool = false

    private let locationManager = LocationManager.shared
    private let speedThreshold: Double = 8.0
    private let minSpeedDuration: TimeInterval = 5.0

    private var speedDetectionStartTime: Date?
    private var speedCheckTimer: Timer?
    private var lastRecordingAttemptTime: Date?

    override init() {
        super.init()
        setupSpeedMonitoring()
    }

    private func setupSpeedMonitoring() {
        speedCheckTimer?.invalidate()
        speedCheckTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.checkDrivingStatus()
        }
    }

    private func checkDrivingStatus() {
        guard isAutoStartEnabled else { return }

        let currentSpeed = locationManager.currentSpeed

        if currentSpeed > speedThreshold {
            if speedDetectionStartTime == nil {
                speedDetectionStartTime = Date()
            }

            let duration = Date().timeIntervalSince(speedDetectionStartTime ?? Date())
            if duration >= minSpeedDuration && !isDriving {
                isDriving = true
                logAutoStart("Driving detected - speed: \(String(format: "%.1f", currentSpeed)) km/h")
            }
        } else {
            if isDriving {
                isDriving = false
                speedDetectionStartTime = nil
                logAutoStart("Driving stopped - speed below threshold")
            } else {
                speedDetectionStartTime = nil
            }
        }
    }

    func shouldAutoStartRecording() -> Bool {
        return isAutoStartEnabled && isDriving
    }

    func resetAutoStartState() {
        speedDetectionStartTime = nil
        isDriving = false
    }

    private func logAutoStart(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[AutoStart] [\(timestamp)] \(message)")
    }

    deinit {
        speedCheckTimer?.invalidate()
    }
}
