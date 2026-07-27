import Foundation
import CoreMotion
import SwiftUI

@MainActor
final class GForceMonitor: NSObject, ObservableObject {
    static let shared = GForceMonitor()

    @Published var currentGForce: Double = 0.0
    @Published var peakGForce: Double = 0.0
    @Published var averageGForce: Double = 0.0
    @Published var accelerometerData: (x: Double, y: Double, z: Double) = (0, 0, 0)
    @Published var isEnabled: Bool = UserDefaults.standard.bool(forKey: "gForceMonitoringEnabled") {
        didSet {
            UserDefaults.standard.set(isEnabled, forKey: "gForceMonitoringEnabled")
        }
    }

    private let motionManager = CMMotionManager()
    private var gForceHistory: [Double] = []
    private let historySize = 300
    private let gravityConstant: Double = 9.81

    override init() {
        let savedEnabled = UserDefaults.standard.object(forKey: "gForceMonitoringEnabled")
        self._isEnabled = Published(initialValue: savedEnabled as? Bool ?? true)
        super.init()
        setupMotionMonitoring()
    }

    private func setupMotionMonitoring() {
        guard motionManager.isAccelerometerAvailable else {
            print("Accelerometer not available for g-force monitoring")
            return
        }

        motionManager.accelerometerUpdateInterval = 0.016
    }

    func startMonitoring() {
        guard motionManager.isAccelerometerAvailable else { return }

        motionManager.startAccelerometerUpdates(to: .main) { [weak self] data, error in
            guard let self = self, let data = data else { return }
            self.processAccelerometerData(data)
        }
    }

    func stopMonitoring() {
        motionManager.stopAccelerometerUpdates()
        peakGForce = 0.0
        averageGForce = 0.0
        gForceHistory.removeAll()
    }

    private func processAccelerometerData(_ data: CMAccelerometerData) {
        guard isEnabled else { return }

        let x = data.acceleration.x
        let y = data.acceleration.y
        let z = data.acceleration.z - gravityConstant

        accelerometerData = (x, y, z)

        let magnitude = sqrt(x * x + y * y + z * z) / gravityConstant
        currentGForce = magnitude

        gForceHistory.append(magnitude)
        if gForceHistory.count > historySize {
            gForceHistory.removeFirst()
        }

        if magnitude > peakGForce {
            peakGForce = magnitude

            if magnitude > 0.5 {
                logGForceEvent(magnitude)
            }
        }

        averageGForce = gForceHistory.isEmpty ? 0 : gForceHistory.reduce(0, +) / Double(gForceHistory.count)
    }

    private func logGForceEvent(_ gForce: Double) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let direction = getGForceDirection()
        print("[GForce] [\(timestamp)] Peak: \(String(format: "%.2f", gForce))G - Direction: \(direction)")
    }

    private func getGForceDirection() -> String {
        let (x, y, z) = accelerometerData
        let absX = abs(x)
        let absY = abs(y)
        let absZ = abs(z)

        if absX > absY && absX > absZ {
            return x > 0 ? "Lateral Right" : "Lateral Left"
        } else if absY > absX && absY > absZ {
            return y > 0 ? "Forward" : "Backward"
        } else {
            return z > 0 ? "Down" : "Up"
        }
    }

    func getGForceString() -> String {
        return String(format: "%.2f G", currentGForce)
    }

    func getPeakGForceString() -> String {
        return String(format: "%.2f G", peakGForce)
    }

    func getAverageGForceString() -> String {
        return String(format: "%.2f G", averageGForce)
    }

    func resetPeakGForce() {
        peakGForce = 0.0
    }
}
