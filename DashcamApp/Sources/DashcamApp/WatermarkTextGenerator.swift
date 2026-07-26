import Foundation

class WatermarkTextGenerator {
    private let fpsCounter: FPSCounter
    private let batteryManager: BatteryMonitorManager
    private let locationManager: LocationManager
    private let dateFormatter: DateFormatter

    init(fpsCounter: FPSCounter, batteryManager: BatteryMonitorManager, locationManager: LocationManager) {
        self.fpsCounter = fpsCounter
        self.batteryManager = batteryManager
        self.locationManager = locationManager

        self.dateFormatter = DateFormatter()
        self.dateFormatter.dateFormat = "HH:mm:ss"
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
}
