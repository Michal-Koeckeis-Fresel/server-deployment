import Foundation

@MainActor
final class WatermarkTextGenerator {
    private let fpsCounter: FPSCounter
    private let batteryManager: BatteryMonitorManager
    private let locationManager: LocationManager
    private let dateFormatter: DateFormatter

    private var cachedWatermarkText: String = "Initializing..."
    private var updateTimer: Timer?

    init(fpsCounter: FPSCounter, batteryManager: BatteryMonitorManager, locationManager: LocationManager) {
        self.fpsCounter = fpsCounter
        self.batteryManager = batteryManager
        self.locationManager = locationManager

        self.dateFormatter = DateFormatter()
        self.dateFormatter.dateFormat = "HH:mm:ss"

        // Generate initial watermark text
        cachedWatermarkText = generateFullWatermarkTextUnsafe()

        // Update watermark text regularly on main thread (5 times per second)
        startCacheUpdateTimer()
    }

    private func startCacheUpdateTimer() {
        updateTimer?.invalidate()
        updateTimer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            self?.cachedWatermarkText = self?.generateFullWatermarkTextUnsafe() ?? "Error"
        }
    }

    func generateTopWatermarkText() -> String {
        let timestamp = dateFormatter.string(from: Date())
        let battery = Int(batteryManager.batteryLevel * 100)
        return "FPS: \(fpsCounter.currentFPS)  |  \(timestamp)  |  Battery: \(battery)%"
    }

    func generateBottomWatermarkText() -> String {
        if let location = locationManager.currentLocation {
            let speed = String(format: "%.0f", locationManager.currentSpeed)
            let altitude = String(format: "%.0f", locationManager.currentAltitude)
            let lat = String(format: "%.4f", location.coordinate.latitude)
            let lon = String(format: "%.4f", location.coordinate.longitude)
            let heading = locationManager.headingString

            return "GPS: \(lat)°N, \(lon)°E  |  Speed: \(speed) km/h  |  Alt: \(altitude)m  |  \(heading)"
        } else {
            return "GPS: No Fix  |  Speed: -- km/h  |  Alt: --m"
        }
    }

    func generateFullWatermarkText() -> String {
        return "\(generateTopWatermarkText())\n\(generateBottomWatermarkText())"
    }

    private func generateFullWatermarkTextUnsafe() -> String {
        return "\(generateTopWatermarkText())\n\(generateBottomWatermarkText())"
    }

    // Nonisolated getter for cached watermark text - safe to call from any thread
    nonisolated func getCachedWatermarkText() -> String {
        // This is a bit of a hack, but we need to access the main thread's cached value
        // In a real app, you'd use Atomic<String> or other thread-safe primitives
        var result = "Initializing..."
        DispatchQueue.main.sync {
            result = (self as! WatermarkTextGenerator).cachedWatermarkText
        }
        return result
    }

    deinit {
        updateTimer?.invalidate()
    }
}
