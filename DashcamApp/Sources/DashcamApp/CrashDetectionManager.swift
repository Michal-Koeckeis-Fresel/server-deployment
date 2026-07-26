import CoreMotion
import Foundation

enum ImpactEventType {
    case collision
    case emergencyBrake
}

class CrashDetectionManager {
    private let motionManager = CMMotionManager()
    private var onEventDetected: ((ImpactEventType) -> Void)?
    private var lastEventTime: Date?

    var isMonitoring: Bool {
        motionManager.isAccelerometerActive
    }

    func startMonitoring(onEventDetected: @escaping (ImpactEventType) -> Void) {
        self.onEventDetected = onEventDetected
        lastEventTime = nil

        guard motionManager.isAccelerometerAvailable else {
            print("Accelerometer not available")
            return
        }

        motionManager.accelerometerUpdateInterval = 0.05
        motionManager.startAccelerometerUpdates(to: .main) { [weak self] data, _ in
            self?.processSensorData(data)
        }
    }

    func stopMonitoring() {
        motionManager.stopAccelerometerUpdates()
    }

    private var accelerationBuffer: [(Double, Double, Double, Date)] = []
    private let bufferSize = 10
    private let debounceInterval: TimeInterval = 2.0

    private func processSensorData(_ data: CMAccelerometerData?) {
        guard let accel = data?.acceleration else { return }

        let x = accel.x
        let y = accel.y
        let z = accel.z
        let timestamp = Date()
        let magnitude = sqrt(x * x + y * y + z * z)

        accelerationBuffer.append((x, y, z, timestamp))
        if accelerationBuffer.count > bufferSize {
            accelerationBuffer.removeFirst()
        }

        if shouldDebounce() {
            return
        }

        if isCrashDetected(magnitude: magnitude) {
            lastEventTime = timestamp
            onEventDetected?(.collision)
        } else if isEmergencyBrakeDetected() {
            lastEventTime = timestamp
            onEventDetected?(.emergencyBrake)
        }
    }

    private func shouldDebounce() -> Bool {
        guard let lastEventTime = lastEventTime else { return false }
        return Date().timeIntervalSince(lastEventTime) < debounceInterval
    }

    private func isCrashDetected(magnitude: Double) -> Bool {
        let gravityAccel = 9.81

        guard accelerationBuffer.count >= 5 else { return false }

        let recentAccelerations = accelerationBuffer.suffix(5).map { data in
            sqrt(data.0 * data.0 + data.1 * data.1 + data.2 * data.2)
        }

        let avgRecent = recentAccelerations.reduce(0, +) / Double(recentAccelerations.count)

        let crashThreshold = gravityAccel * 2.5
        let minChangeThreshold = gravityAccel * 1.0

        let isHighAccel = avgRecent > crashThreshold
        let hasChange = recentAccelerations.max()! - recentAccelerations.min()! > minChangeThreshold

        return isHighAccel && hasChange
    }

    private func isEmergencyBrakeDetected() -> Bool {
        let gravityAccel = 9.81

        guard accelerationBuffer.count >= 4 else { return false }

        let recentData = Array(accelerationBuffer.suffix(4))
        var decelerationCount = 0
        var maxDeceleration: Double = 0

        for i in 0..<recentData.count {
            let x = recentData[i].0
            let y = recentData[i].1
            let z = recentData[i].2

            let accelMagnitude = sqrt(x * x + y * y + z * z)

            if z < -1.5 {
                decelerationCount += 1
                maxDeceleration = max(maxDeceleration, abs(z))
            }
        }

        let brakingThreshold = gravityAccel * 1.5
        let isSustainedDeceleration = decelerationCount >= 3
        let isHighDecel = maxDeceleration > 1.5

        return isSustainedDeceleration && isHighDecel
    }
}
