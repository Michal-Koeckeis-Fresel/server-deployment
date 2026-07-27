import Foundation

class iCloudStorageManager {
    static let shared = iCloudStorageManager()

    private let fileManager = FileManager.default
    private var iCloudContainerURL: URL?

    init() {
        setupiCloudContainer()
    }

    private func setupiCloudContainer() {
        guard let containerURL = fileManager.url(forUbiquityContainerIdentifier: nil) else {
            print("iCloud container not available - ensure iCloud capability is enabled in Xcode")
            return
        }

        iCloudContainerURL = containerURL.appendingPathComponent("Documents")

        do {
            try fileManager.createDirectory(
                at: iCloudContainerURL!,
                withIntermediateDirectories: true
            )
            print("✓ iCloud container ready at: \(iCloudContainerURL?.path ?? "unknown")")
        } catch {
            print("✗ Failed to create iCloud directory: \(error)")
            iCloudContainerURL = nil
        }
    }

    var isiCloudAvailable: Bool {
        iCloudContainerURL != nil
    }

    func getRecordingsURL() -> URL? {
        guard let container = iCloudContainerURL else { return nil }
        let recordingsURL = container.appendingPathComponent("Recordings")

        do {
            try fileManager.createDirectory(
                at: recordingsURL,
                withIntermediateDirectories: true
            )
            return recordingsURL
        } catch {
            print("✗ Failed to create Recordings directory: \(error)")
            return nil
        }
    }

    func copyFileToiCloud(from localURL: URL) async -> URL? {
        guard let recordingsURL = getRecordingsURL() else {
            print("✗ iCloud not available")
            return nil
        }

        let fileName = localURL.lastPathComponent
        let iCloudURL = recordingsURL.appendingPathComponent(fileName)

        do {
            try fileManager.copyItem(at: localURL, to: iCloudURL)

            var resourceValues = URLResourceValues()
            resourceValues.isUbiquitousItem = true
            try iCloudURL.setResourceValues(resourceValues)

            print("✓ Copied to iCloud: \(fileName)")
            return iCloudURL
        } catch {
            print("✗ Failed to copy to iCloud: \(error)")
            return nil
        }
    }

    func deleteFromiCloud(_ url: URL) async {
        do {
            try fileManager.removeItem(at: url)
            print("✓ Deleted from iCloud: \(url.lastPathComponent)")
        } catch {
            print("✗ Failed to delete from iCloud: \(error)")
        }
    }

    func getiCloudFileSize(at url: URL) -> Double {
        do {
            let attributes = try fileManager.attributesOfItem(atPath: url.path)
            let fileSize = (attributes[.size] as? NSNumber)?.doubleValue ?? 0
            return fileSize / (1024 * 1024 * 1024)
        } catch {
            return 0.0
        }
    }

    func calculateTotaliCloudUsage() -> Double {
        guard let recordingsURL = getRecordingsURL() else { return 0.0 }

        do {
            let files = try fileManager.contentsOfDirectory(
                at: recordingsURL,
                includingPropertiesForKeys: [.fileSizeKey]
            )

            let totalBytes = files.reduce(0) { sum, url in
                let resources = try? url.resourceValues(forKeys: [.fileSizeKey])
                return sum + (resources?.fileSize ?? 0)
            }

            return Double(totalBytes) / (1024 * 1024 * 1024)
        } catch {
            return 0.0
        }
    }

    func listiCloudRecordings() async -> [URL] {
        guard let recordingsURL = getRecordingsURL() else { return [] }

        do {
            let files = try fileManager.contentsOfDirectory(
                at: recordingsURL,
                includingPropertiesForKeys: [.contentModificationDateKey]
            ).filter { $0.pathExtension == "mov" }

            return files.sorted { url1, url2 in
                let date1 = (try? url1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? Date()
                let date2 = (try? url2.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? Date()
                return date1 > date2
            }
        } catch {
            print("✗ Failed to list iCloud recordings: \(error)")
            return []
        }
    }
}
