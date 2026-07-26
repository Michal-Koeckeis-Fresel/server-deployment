import Foundation

class StorageManager {
    func calculateUsedStorage(at path: URL) -> Double {
        do {
            let files = try FileManager.default.contentsOfDirectory(
                at: path,
                includingPropertiesForKeys: [.fileSizeKey]
            ).filter { $0.pathExtension == "mov" }

            let totalBytes = files.reduce(0) { sum, url in
                let resources = try? url.resourceValues(forKeys: [.fileSizeKey])
                return sum + (resources?.fileSize ?? 0)
            }

            return Double(totalBytes) / (1024 * 1024 * 1024)
        } catch {
            return 0.0
        }
    }

    func checkAndCleanupIfNeeded(maxStorageGB: Double, protectionManager: FileProtectionManager) async {
        let docPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let currentUsage = calculateUsedStorage(at: docPath)

        if currentUsage > maxStorageGB {
            await deleteOldestUnprotectedFiles(at: docPath, protectionManager: protectionManager, maxStorageGB: maxStorageGB)
        }
    }

    private func deleteOldestUnprotectedFiles(
        at path: URL,
        protectionManager: FileProtectionManager,
        maxStorageGB: Double
    ) async {
        do {
            var files = try FileManager.default.contentsOfDirectory(
                at: path,
                includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey]
            ).filter { $0.pathExtension == "mov" }

            files.sort { url1, url2 in
                let date1 = (try? url1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? Date()
                let date2 = (try? url2.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? Date()
                return date1 < date2
            }

            var currentUsage = calculateUsedStorage(at: path)

            for file in files {
                if currentUsage <= maxStorageGB {
                    break
                }

                if !protectionManager.isProtected(url: file) {
                    let fileSize = (try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                    try FileManager.default.removeItem(at: file)
                    currentUsage -= Double(fileSize) / (1024 * 1024 * 1024)
                }
            }
        } catch {
            print("Storage cleanup error: \(error.localizedDescription)")
        }
    }

    func deleteFile(at url: URL) -> Bool {
        do {
            try FileManager.default.removeItem(at: url)
            return true
        } catch {
            return false
        }
    }
}
