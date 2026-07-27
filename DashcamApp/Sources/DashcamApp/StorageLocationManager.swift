import Foundation
import Network

enum StorageLocation: String, CaseIterable {
    case onDevice = "On Device (Local)"
    case iCloud = "iCloud Drive"
    case iCloudWiFiOnly = "iCloud Drive (Wi-Fi Only)"
    case iCloudLocal = "iCloud Folder (Local Only)"
    case iCloudLocalBackup = "iCloud Folder with Cloud Backup"
    case filesApp = "Files App Folder"

    var displayName: String {
        self.rawValue
    }

    var description: String {
        switch self {
        case .onDevice:
            return "Stores on device only. Deleted if app is uninstalled."
        case .iCloud:
            return "Stores in iCloud Drive. Persists even if app is uninstalled."
        case .iCloudWiFiOnly:
            return "Stores in iCloud but only syncs over Wi-Fi. Prevents cellular data usage."
        case .iCloudLocal:
            return "Stores in iCloud folder without uploading. Persists but no cellular data used."
        case .iCloudLocalBackup:
            return "Stores locally in iCloud folder and automatically backs up to iCloud Drive."
        case .filesApp:
            return "Organized folder in Files app. Access via Files, iCloud Drive, or Mac."
        }
    }

    var warningMessage: String {
        switch self {
        case .onDevice:
            return "⚠️ Files will be deleted when app is uninstalled!"
        case .iCloud:
            return "✅ Files persist in iCloud even if app is uninstalled."
        case .iCloudWiFiOnly:
            return "✅ Files sync to iCloud but only over Wi-Fi to save cellular data."
        case .iCloudLocal:
            return "✅ Files persist but stay local - no cloud sync or cellular data used."
        case .iCloudLocalBackup:
            return "✅ Protected locally + auto-backed up to iCloud. Double protection."
        case .filesApp:
            return "✅ Files persist in Files app folder. Accessible after uninstall."
        }
    }
}

class StorageLocationManager {
    static let shared = StorageLocationManager()
    private let storageLocationKey = "selectedStorageLocation"
    private let fileManager = FileManager.default

    var selectedLocation: StorageLocation {
        get {
            if let saved = UserDefaults.standard.string(forKey: storageLocationKey),
               let location = StorageLocation(rawValue: saved) {
                return location
            }
            return .iCloud
        }
        set {
            UserDefaults.standard.set(newValue.rawValue, forKey: storageLocationKey)
        }
    }

    func getRecordingsURL() -> URL? {
        switch selectedLocation {
        case .onDevice:
            return fileManager.urls(for: .documentDirectory, in: .userDomainMask).first

        case .iCloud:
            guard let iCloudContainerURL = fileManager.url(
                forUbiquityContainerIdentifier: nil
            ) else {
                return nil
            }

            let dashcamFolder = iCloudContainerURL.appendingPathComponent("Dashcam Recordings", isDirectory: true)

            do {
                try fileManager.createDirectory(
                    at: dashcamFolder,
                    withIntermediateDirectories: true,
                    attributes: nil
                )
                return dashcamFolder
            } catch {
                print("Failed to create iCloud directory: \(error)")
                return nil
            }

        case .iCloudWiFiOnly:
            guard let iCloudContainerURL = fileManager.url(
                forUbiquityContainerIdentifier: nil
            ) else {
                return nil
            }

            let dashcamFolder = iCloudContainerURL.appendingPathComponent("Dashcam Recordings WiFi", isDirectory: true)

            do {
                try fileManager.createDirectory(
                    at: dashcamFolder,
                    withIntermediateDirectories: true,
                    attributes: nil
                )
                return dashcamFolder
            } catch {
                print("Failed to create iCloud Wi-Fi only directory: \(error)")
                return nil
            }

        case .iCloudLocal:
            guard let iCloudContainerURL = fileManager.url(
                forUbiquityContainerIdentifier: nil
            ) else {
                return nil
            }

            let dashcamFolder = iCloudContainerURL.appendingPathComponent("Dashcam Recordings Local", isDirectory: true)

            do {
                try fileManager.createDirectory(
                    at: dashcamFolder,
                    withIntermediateDirectories: true,
                    attributes: nil
                )
                return dashcamFolder
            } catch {
                print("Failed to create iCloud local directory: \(error)")
                return nil
            }

        case .iCloudLocalBackup:
            guard let iCloudContainerURL = fileManager.url(
                forUbiquityContainerIdentifier: nil
            ) else {
                return nil
            }

            let dashcamFolder = iCloudContainerURL.appendingPathComponent("Dashcam Recordings Protected", isDirectory: true)

            do {
                try fileManager.createDirectory(
                    at: dashcamFolder,
                    withIntermediateDirectories: true,
                    attributes: nil
                )
                return dashcamFolder
            } catch {
                print("Failed to create iCloud protected directory: \(error)")
                return nil
            }

        case .filesApp:
            guard let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
                return nil
            }
            let dashcamFolder = documentsURL.appendingPathComponent("Dashcam Recordings", isDirectory: true)
            do {
                try fileManager.createDirectory(
                    at: dashcamFolder,
                    withIntermediateDirectories: true,
                    attributes: nil
                )
                return dashcamFolder
            } catch {
                print("Failed to create Files app folder: \(error)")
                return nil
            }
        }
    }

    func isICloudAvailable() -> Bool {
        return fileManager.url(forUbiquityContainerIdentifier: nil) != nil
    }

    func isConnectedToWiFi() -> Bool {
        let monitor = NWPathMonitor()
        defer { monitor.cancel() }

        let semaphore = DispatchSemaphore(value: 0)
        var isWiFi = false

        monitor.pathUpdateHandler = { path in
            isWiFi = path.usesInterfaceType(.wifi)
            semaphore.signal()
        }

        let queue = DispatchQueue(label: "com.dashcam.wifi.check")
        monitor.start(queue: queue)

        _ = semaphore.wait(timeout: .now() + 1.0)
        return isWiFi
    }

    func getBackupURL() -> URL? {
        guard selectedLocation == .iCloudLocalBackup else {
            return nil
        }

        guard let iCloudContainerURL = fileManager.url(
            forUbiquityContainerIdentifier: nil
        ) else {
            return nil
        }

        let backupFolder = iCloudContainerURL.appendingPathComponent("Dashcam Recordings Backup", isDirectory: true)

        do {
            try fileManager.createDirectory(
                at: backupFolder,
                withIntermediateDirectories: true,
                attributes: nil
            )
            return backupFolder
        } catch {
            print("Failed to create iCloud backup directory: \(error)")
            return nil
        }
    }

    func getStorageInfo() -> (used: Double, location: String) {
        guard let url = getRecordingsURL() else {
            return (0.0, "No Storage")
        }

        do {
            let files = try fileManager.contentsOfDirectory(
                at: url,
                includingPropertiesForKeys: [.fileSizeKey]
            ).filter { $0.pathExtension == "mov" }

            let totalBytes = files.reduce(0) { sum, fileURL in
                let resources = try? fileURL.resourceValues(forKeys: [.fileSizeKey])
                return sum + (resources?.fileSize ?? 0)
            }

            let gb = Double(totalBytes) / (1024 * 1024 * 1024)
            let locationName = selectedLocation.displayName

            return (gb, locationName)
        } catch {
            return (0.0, selectedLocation.displayName)
        }
    }

    func migrateRecordings(from sourceLocation: StorageLocation) {
        guard sourceLocation != selectedLocation else { return }

        guard let sourceURL = getURLForLocation(sourceLocation),
              let destURL = getRecordingsURL() else {
            return
        }

        do {
            let files = try fileManager.contentsOfDirectory(
                at: sourceURL,
                includingPropertiesForKeys: nil
            ).filter { $0.pathExtension == "mov" }

            for file in files {
                let destFile = destURL.appendingPathComponent(file.lastPathComponent)
                try? fileManager.copyItem(at: file, to: destFile)
            }
        } catch {
            print("Migration error: \(error)")
        }
    }

    private func getURLForLocation(_ location: StorageLocation) -> URL? {
        switch location {
        case .onDevice:
            return fileManager.urls(for: .documentDirectory, in: .userDomainMask).first

        case .iCloud:
            guard let iCloudContainerURL = fileManager.url(
                forUbiquityContainerIdentifier: nil
            ) else {
                return nil
            }
            return iCloudContainerURL.appendingPathComponent("Dashcam Recordings", isDirectory: true)

        case .iCloudWiFiOnly:
            guard let iCloudContainerURL = fileManager.url(
                forUbiquityContainerIdentifier: nil
            ) else {
                return nil
            }
            return iCloudContainerURL.appendingPathComponent("Dashcam Recordings WiFi", isDirectory: true)

        case .iCloudLocal:
            guard let iCloudContainerURL = fileManager.url(
                forUbiquityContainerIdentifier: nil
            ) else {
                return nil
            }
            return iCloudContainerURL.appendingPathComponent("Dashcam Recordings Local", isDirectory: true)

        case .iCloudLocalBackup:
            guard let iCloudContainerURL = fileManager.url(
                forUbiquityContainerIdentifier: nil
            ) else {
                return nil
            }
            return iCloudContainerURL.appendingPathComponent("Dashcam Recordings Protected", isDirectory: true)

        case .filesApp:
            return fileManager.urls(for: .documentDirectory, in: .userDomainMask).first
                .map { $0.appendingPathComponent("Dashcam Recordings", isDirectory: true) }
        }
    }

}
