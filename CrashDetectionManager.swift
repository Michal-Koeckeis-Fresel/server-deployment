import CoreMotion
import Foundation

class CrashDetectionManager {
    private let motionManager = CMMotionManager()
    private var onCrashDetected: (() -> Void)?

    var isMonitoring: Bool {
        motionManager.isAccelerometerActive
    }

    func startMonitoring(onCrashDetected: @escaping () -> Void) {
        self.onCrashDetected = onCrashDetected

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

    private var accelerationBuffer: [(Double, Double, Double)] = []
    private let bufferSize = 10

    private func processSensorData(_ data: CMAccelerometerData?) {
        guard let accel = data?.acceleration else { return }

        let x = accel.x
        let y = accel.y
        let z = accel.z
        let magnitude = sqrt(x * x + y * y + z * z)

        accelerationBuffer.append((x, y, z))
        if accelerationBuffer.count > bufferSize {
            accelerationBuffer.removeFirst()
        }

        if isCrashDetected(magnitude: magnitude) {
            onCrashDetected?()
            stopMonitoring()
        }
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
}
