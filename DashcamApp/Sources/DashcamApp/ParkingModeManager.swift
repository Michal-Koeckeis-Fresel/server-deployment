import Foundation
import CoreMotion
import SwiftUI

class ParkingModeManager: NSObject, ObservableObject {
    static let shared = ParkingModeManager()

    @Published var isParkingModeEnabled: Bool = UserDefaults.standard.bool(forKey: "parkingModeEnabled") {
        didSet {
            UserDefaults.standard.set(isParkingModeEnabled, forKey: "parkingModeEnabled")
        }
    }

    @Published var isParked: Bool = false
    @Published var parkingMotionDetected: Bool = false
    @Published var parkingRecordingActive: Bool = false

    private let motionManager = CMMotionManager()
    private let accelerometerThreshold: Double = 0.3
    private let parkingDetectionDelay: TimeInterval = 120
    private let motionDetectionThreshold: Double = 0.5

    private var stationaryStartTime: Date?
    private var parkingTimer: Timer?
    private var motionDetectionTimer: Timer?

    override init() {
        super.init()
        setupMotionDetection()
    }

    private func setupMotionDetection() {
        guard motionManager.isAccelerometerAvailable else {
            print("Accelerometer not available")
            return
        }

        motionManager.accelerometerUpdateInterval = 0.1
    }

    func startParkingModeMonitoring() {
        guard isParkingModeEnabled else { return }

        motionManager.startAccelerometerUpdates(to: .main) { [weak self] data, error in
            guard let self = self, let data = data else { return }

            let acceleration = data.acceleration
            let magnitude = sqrt(acceleration.x * acceleration.x +
                               acceleration.y * acceleration.y +
                               acceleration.z * acceleration.z)

            if magnitude < self.accelerometerThreshold {
                self.handleStationaryMotion()
            } else {
                self.handleActiveMotion()
            }
        }

        setupParkingTimer()
        logParkingEvent("Parking mode monitoring started")
    }

    func stopParkingModeMonitoring() {
        motionManager.stopAccelerometerUpdates()
        parkingTimer?.invalidate()
        parkingTimer = nil
        motionDetectionTimer?.invalidate()
        motionDetectionTimer = nil
        stationaryStartTime = nil
        isParked = false
        parkingRecordingActive = false
        logParkingEvent("Parking mode monitoring stopped")
    }

    private func handleStationaryMotion() {
        if stationaryStartTime == nil {
            stationaryStartTime = Date()
        }
    }

    private func handleActiveMotion() {
        if isParked {
            parkingMotionDetected = true
            logParkingEvent("Motion detected while parked - protecting recordings")
        }
        stationaryStartTime = nil
    }

    private func setupParkingTimer() {
        parkingTimer?.invalidate()
        parkingTimer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
            self?.checkParkingStatus()
        }
    }

    private func checkParkingStatus() {
        guard let stationaryStart = stationaryStartTime else {
            if isParked {
                isParked = false
                logParkingEvent("Vehicle movement detected - exiting parking mode")
            }
            return
        }

        let stationaryDuration = Date().timeIntervalSince(stationaryStart)

        if stationaryDuration >= parkingDetectionDelay && !isParked {
            isParked = true
            parkingMotionDetected = false
            logParkingEvent("Vehicle parked - entering parking mode")
        }
    }

    func enableParkingRecording() {
        guard isParked else { return }
        parkingRecordingActive = true
        logParkingEvent("Parking mode recording enabled")
    }

    func disableParkingRecording() {
        parkingRecordingActive = false
        logParkingEvent("Parking mode recording disabled")
    }

    var parkingStatusDescription: String {
        if isParked {
            return parkingMotionDetected ? "🚨 Parked - Motion Detected!" : "🅿️ Parked - Monitoring"
        }
        return "🚗 Driving"
    }

    private func logParkingEvent(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[Parking] [\(timestamp)] \(message)")
    }
}
