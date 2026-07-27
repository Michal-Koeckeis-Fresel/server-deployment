import Foundation
@preconcurrency import CoreLocation
import SwiftUI

class LocationManager: NSObject, ObservableObject, CLLocationManagerDelegate {
    static let shared = LocationManager()

    @Published var currentLocation: CLLocation?
    @Published var currentSpeed: Double = 0.0
    @Published var currentAltitude: Double = 0.0
    @Published var currentHeading: Double = 0.0
    @Published var isLocationAvailable: Bool = false

    private let locationManager = CLLocationManager()
    private var authorizationStatus: CLAuthorizationStatus = .notDetermined

    override init() {
        super.init()
        setupLocationManager()
    }

    private func setupLocationManager() {
        locationManager.delegate = self
        locationManager.desiredAccuracy = kCLLocationAccuracyBestForNavigation
        locationManager.activityType = .automotiveNavigation

        authorizationStatus = locationManager.authorizationStatus

        if authorizationStatus == .notDetermined {
            locationManager.requestWhenInUseAuthorization()
        } else if authorizationStatus == .authorizedWhenInUse || authorizationStatus == .authorizedAlways {
            startLocationUpdates()
        }
    }

    func requestLocationPermission() {
        locationManager.requestWhenInUseAuthorization()
    }

    func startLocationUpdates() {
        locationManager.startUpdatingLocation()
        locationManager.startUpdatingHeading()
        isLocationAvailable = true
        logLocation("Location tracking started")
    }

    func stopLocationUpdates() {
        locationManager.stopUpdatingLocation()
        locationManager.stopUpdatingHeading()
        isLocationAvailable = false
        logLocation("Location tracking stopped")
    }

    // MARK: - CLLocationManagerDelegate

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let status = manager.authorizationStatus
            if status == .authorizedWhenInUse || status == .authorizedAlways {
                self.startLocationUpdates()
            } else if status == .denied || status == .restricted {
                self.isLocationAvailable = false
            }
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.last else { return }

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.currentLocation = location
            self.currentSpeed = location.speed > 0 ? location.speed * 3.6 : 0
            self.currentAltitude = location.altitude
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didUpdateHeading newHeading: CLHeading) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.currentHeading = newHeading.trueHeading >= 0 ? newHeading.trueHeading : newHeading.magneticHeading
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.logLocation("Location error: \(error.localizedDescription)")
            self.isLocationAvailable = false
        }
    }

    var locationString: String {
        guard let location = currentLocation else {
            return "GPS: No fix"
        }
        return String(format: "GPS: %.4f°N, %.4f°E", location.coordinate.latitude, location.coordinate.longitude)
    }

    var speedString: String {
        String(format: "%.0f km/h", currentSpeed)
    }

    var altitudeString: String {
        String(format: "%.0f m", currentAltitude)
    }

    var headingString: String {
        let directions = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"]
        let index = Int((currentHeading + 11.25) / 22.5) % 16
        return directions[index]
    }

    func getLocationData() -> (latitude: Double, longitude: Double, speed: Double, altitude: Double, heading: Double)? {
        guard let location = currentLocation else { return nil }
        return (location.coordinate.latitude, location.coordinate.longitude, currentSpeed, currentAltitude, currentHeading)
    }

    func printLocationDiagnostics() {
        print("\n=== Location Diagnostics Report ===")
        print("Timestamp: \(ISO8601DateFormatter().string(from: Date()))")
        print("Location: \(locationString)")
        print("Speed: \(speedString)")
        print("Altitude: \(altitudeString)")
        print("Heading: \(headingString)")
        print("Tracking: \(isLocationAvailable ? "Active" : "Inactive")")
        print("===================================\n")
    }

    private func logLocation(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[Location] [\(timestamp)] \(message)")
    }
}
