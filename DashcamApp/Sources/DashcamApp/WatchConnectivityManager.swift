import Foundation
import WatchConnectivity
import SwiftUI

@available(iOS 14.0, *)
class WatchConnectivityManager: NSObject, ObservableObject, WCSessionDelegate {
    static let shared = WatchConnectivityManager()

    @Published var isWatchPaired: Bool = false
    @Published var isWatchReachable: Bool = false
    @Published var lastMessageSent: Date?
    @Published var watchAlertLog: [WatchAlert] = []

    struct WatchAlert {
        let type: AlertType
        let timestamp: Date
        let message: String

        enum AlertType: String {
            case collision = "Collision"
            case emergencyBrake = "Emergency Brake"
            case airbagDeployed = "Airbag Deployed"
            case glassBreak = "Glass Break"
            case recordingStarted = "Recording Started"
            case recordingStopped = "Recording Stopped"
            case parkingMotion = "Parking Motion"
            case thermalAlert = "Thermal Alert"
            case batteryAlert = "Battery Alert"
        }
    }

    private var wcSession: WCSession?
    private let alertMaxSize = 50

    override init() {
        super.init()
        setupWatchConnectivity()
    }

    private func setupWatchConnectivity() {
        guard WCSession.isSupported() else {
            print("WatchKit not supported on this device")
            return
        }

        let session = WCSession.default
        session.delegate = self
        session.activate()
        wcSession = session

        DispatchQueue.main.async {
            self.updateWatchStatus()
        }
    }

    private func updateWatchStatus() {
        guard let session = wcSession else { return }

        isWatchPaired = session.isPaired
        isWatchReachable = session.isReachable

        print("Watch Status - Paired: \(isWatchPaired), Reachable: \(isWatchReachable)")
    }

    func sendCrashAlert(type: String = "Collision") {
        let alert = WatchAlert(
            type: .collision,
            timestamp: Date(),
            message: "🚨 CRASH DETECTED! Recording protected."
        )
        sendAlert(alert, with: [
            "type": "crash",
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "message": "Collision detected - recording protected"
        ])
    }

    func sendEmergencyBrakeAlert() {
        let alert = WatchAlert(
            type: .emergencyBrake,
            timestamp: Date(),
            message: "🛑 EMERGENCY BRAKE DETECTED!"
        )
        sendAlert(alert, with: [
            "type": "emergency_brake",
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "message": "Emergency braking event detected"
        ])
    }

    func sendAirbagAlert() {
        let alert = WatchAlert(
            type: .airbagDeployed,
            timestamp: Date(),
            message: "⚠️ AIRBAG DEPLOYMENT DETECTED!"
        )
        sendAlert(alert, with: [
            "type": "airbag",
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "message": "Airbag deployment sound detected - EMERGENCY"
        ])
    }

    func sendGlassBreakAlert() {
        let alert = WatchAlert(
            type: .glassBreak,
            timestamp: Date(),
            message: "🚨 GLASS BREAK DETECTED!"
        )
        sendAlert(alert, with: [
            "type": "glass_break",
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "message": "Glass breaking sound detected"
        ])
    }

    func sendParkingMotionAlert() {
        let alert = WatchAlert(
            type: .parkingMotion,
            timestamp: Date(),
            message: "🚨 MOTION DETECTED WHILE PARKED!"
        )
        sendAlert(alert, with: [
            "type": "parking_motion",
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "message": "Motion detected while parked - recordings protected"
        ])
    }

    func sendRecordingStatusAlert(isRecording: Bool) {
        let type: WatchAlert.AlertType = isRecording ? .recordingStarted : .recordingStopped
        let message = isRecording ? "📹 Recording started" : "⏹️ Recording stopped"

        let alert = WatchAlert(
            type: type,
            timestamp: Date(),
            message: message
        )
        sendAlert(alert, with: [
            "type": isRecording ? "recording_started" : "recording_stopped",
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "message": message
        ])
    }

    func sendThermalAlert(level: String) {
        let alert = WatchAlert(
            type: .thermalAlert,
            timestamp: Date(),
            message: "🌡️ Thermal alert: \(level)"
        )
        sendAlert(alert, with: [
            "type": "thermal",
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "level": level,
            "message": "Device thermal pressure detected"
        ])
    }

    func sendBatteryAlert(level: Int) {
        let type: WatchAlert.AlertType = level < 10 ? .batteryAlert : .batteryAlert
        let message = level < 10 ? "🔴 CRITICAL BATTERY - \(level)%" : "🟠 Low battery - \(level)%"

        let alert = WatchAlert(
            type: type,
            timestamp: Date(),
            message: message
        )
        sendAlert(alert, with: [
            "type": "battery",
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "level": String(level),
            "message": message
        ])
    }

    func sendRecordingMetrics(
        fps: Double,
        memory: Double,
        storage: Double,
        gForce: Double
    ) {
        guard isWatchReachable else { return }

        let data: [String: Any] = [
            "type": "metrics",
            "fps": String(format: "%.1f", fps),
            "memory": String(format: "%.0f", memory),
            "storage": String(format: "%.1f", storage),
            "gforce": String(format: "%.2f", gForce),
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]

        sendToWatch(data)
    }

    func sendAlert(_ alert: WatchAlert, with data: [String: Any]) {
        DispatchQueue.main.async {
            self.watchAlertLog.append(alert)
            if self.watchAlertLog.count > self.alertMaxSize {
                self.watchAlertLog.removeFirst()
            }
        }

        sendToWatch(data)
    }

    private func sendToWatch(_ data: [String: Any]) {
        guard isWatchPaired, isWatchReachable else {
            print("Watch not reachable for message: \(data)")
            return
        }

        wcSession?.sendMessage(data, replyHandler: { response in
            print("Watch acknowledged: \(response)")
            DispatchQueue.main.async {
                self.lastMessageSent = Date()
            }
        }, errorHandler: { error in
            print("Error sending message to watch: \(error)")
        })
    }

    func updateApplicationContext(_ data: [String: Any]) {
        guard isWatchPaired else { return }

        do {
            try wcSession?.updateApplicationContext(data)
            print("Application context updated")
        } catch {
            print("Error updating application context: \(error)")
        }
    }

    // MARK: - WCSessionDelegate

    func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        DispatchQueue.main.async {
            self.updateWatchStatus()
        }
    }

    func sessionDidBecomeInactive(_ session: WCSession) {
        print("Watch session became inactive")
    }

    func sessionDidDeactivate(_ session: WCSession) {
        print("Watch session deactivated")
        wcSession?.activate()
    }

    func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
        print("Received message from watch: \(message)")
    }

    func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
        print("Received app context from watch: \(applicationContext)")
    }

    func sessionReachabilityDidChange(_ session: WCSession) {
        DispatchQueue.main.async {
            self.isWatchReachable = session.isReachable
            print("Watch reachability changed: \(self.isWatchReachable)")
        }
    }

    func getAlertHistory() -> [WatchAlert] {
        return watchAlertLog
    }

    func clearAlertHistory() {
        watchAlertLog.removeAll()
    }
}
