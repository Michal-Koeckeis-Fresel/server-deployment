import Foundation
import SwiftUI
import Contacts

class EmergencySOSManager: NSObject, ObservableObject {
    static let shared = EmergencySOSManager()

    @Published var sosTriggered: Bool = false
    @Published var sosActiveTime: Date?
    @Published var sosContactsEnabled: Bool = UserDefaults.standard.bool(forKey: "sosContactsEnabled") {
        didSet {
            UserDefaults.standard.set(sosContactsEnabled, forKey: "sosContactsEnabled")
        }
    }
    @Published var emergencyContacts: [EmergencyContact] = []
    @Published var lastSOSTimestamp: Date?
    @Published var sosAlertCount: Int = 0

    struct EmergencyContact {
        let name: String
        let phoneNumber: String
        let isWatchEnabled: Bool
    }

    private let sosDebounceInterval: TimeInterval = 5.0
    private var lastSOSTime: Date?
    private var sosTimer: Timer?
    private let sosActiveDuration: TimeInterval = 30.0

    override init() {
        super.init()
        loadEmergencyContacts()
    }

    func triggerSOS() {
        // Debounce SOS to prevent accidental multiple triggers
        if let lastTime = lastSOSTime, Date().timeIntervalSince(lastTime) < sosDebounceInterval {
            print("SOS debounce active - ignoring trigger")
            return
        }

        lastSOSTime = Date()
        sosTriggered = true
        sosActiveTime = Date()
        lastSOSTimestamp = Date()
        sosAlertCount += 1

        logSOSEvent("SOS Triggered")

        // Send to watch
        if #available(iOS 14.0, *) {
            WatchConnectivityManager.shared.sendAlert(
                WatchConnectivityManager.WatchAlert(
                    type: .collision,
                    timestamp: Date(),
                    message: "🚨 SOS ACTIVATED! Emergency assistance requested."
                ),
                with: [
                    "type": "sos_activated",
                    "timestamp": ISO8601DateFormatter().string(from: Date()),
                    "message": "SOS button activated - emergency alert sent"
                ]
            )
        }

        // Notify emergency contacts if enabled
        if sosContactsEnabled {
            notifyEmergencyContacts()
        }

        // Start SOS deactivation timer
        sosTimer?.invalidate()
        sosTimer = Timer.scheduledTimer(withTimeInterval: sosActiveDuration, repeats: false) { [weak self] _ in
            self?.deactivateSOS()
        }

        // Protect all current recordings
        protectAllRecordings()
    }

    func deactivateSOS() {
        sosTriggered = false
        sosTimer?.invalidate()
        sosTimer = nil
        logSOSEvent("SOS Deactivated")
    }

    private func notifyEmergencyContacts() {
        let message = "EMERGENCY: Dashcam SOS activated at \(Date().formatted(date: .abbreviated, time: .standard)). Location and vehicle status recorded."

        for contact in emergencyContacts {
            sendEmergencyMessage(to: contact, message: message)
        }
    }

    private func sendEmergencyMessage(to contact: EmergencyContact, message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[SOS] Sending emergency message to \(contact.name): \(contact.phoneNumber)")
        print("[SOS] [\(timestamp)] Message: \(message)")

        // In a real app, this would integrate with SMS/iMessage APIs
        // For now, we log the intent
    }

    private func protectAllRecordings() {
        // This would be called from the ViewModel to protect all active recordings
        print("[SOS] Protecting all active recordings from deletion")
    }

    private func loadEmergencyContacts() {
        let savedContacts = UserDefaults.standard.array(forKey: "emergencyContacts") as? [[String: Any]] ?? []
        emergencyContacts = savedContacts.compactMap { dict in
            guard let name = dict["name"] as? String,
                  let phone = dict["phone"] as? String else {
                return nil
            }
            let watchEnabled = dict["watchEnabled"] as? Bool ?? false
            return EmergencyContact(name: name, phoneNumber: phone, isWatchEnabled: watchEnabled)
        }
    }

    func saveEmergencyContacts(_ contacts: [EmergencyContact]) {
        let data = contacts.map { contact -> [String: Any] in
            return [
                "name": contact.name,
                "phone": contact.phoneNumber,
                "watchEnabled": contact.isWatchEnabled
            ]
        }
        UserDefaults.standard.set(data, forKey: "emergencyContacts")
        emergencyContacts = contacts
        print("Saved \(contacts.count) emergency contacts")
    }

    func addEmergencyContact(_ name: String, phoneNumber: String, watchEnabled: Bool = true) {
        let newContact = EmergencyContact(name: name, phoneNumber: phoneNumber, isWatchEnabled: watchEnabled)
        emergencyContacts.append(newContact)
        saveEmergencyContacts(emergencyContacts)
    }

    func removeEmergencyContact(at index: Int) {
        guard index >= 0 && index < emergencyContacts.count else { return }
        emergencyContacts.remove(at: index)
        saveEmergencyContacts(emergencyContacts)
    }

    private func logSOSEvent(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[SOS] [\(timestamp)] \(message)")
    }

    func getSOSStatusString() -> String {
        if sosTriggered {
            if let activeTime = sosActiveTime {
                let elapsed = Int(Date().timeIntervalSince(activeTime))
                let remaining = max(0, Int(sosActiveDuration) - elapsed)
                return "🚨 Active - \(remaining)s remaining"
            }
            return "🚨 Active"
        }
        return "Ready"
    }

    func getSOSContactsString() -> String {
        return "\(emergencyContacts.count) contact\(emergencyContacts.count != 1 ? "s" : "")"
    }

    deinit {
        sosTimer?.invalidate()
    }
}
