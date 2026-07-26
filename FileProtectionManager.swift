import Foundation

class FileProtectionManager {
    private let protectionKey = "protected_files"
    private var protectedFiles: Set<String> {
        get {
            let stored = UserDefaults.standard.stringArray(forKey: protectionKey) ?? []
            return Set(stored)
        }
        set {
            UserDefaults.standard.set(Array(newValue), forKey: protectionKey)
        }
    }

    func toggleProtection(for url: URL) {
        let key = url.lastPathComponent
        var protected = protectedFiles

        if protected.contains(key) {
            protected.remove(key)
        } else {
            protected.insert(key)
        }

        protectedFiles = protected
    }

    func isProtected(url: URL) -> Bool {
        let key = url.lastPathComponent
        return protectedFiles.contains(key)
    }

    func setProtection(_ protected: Bool, for url: URL) {
        let key = url.lastPathComponent
        var protected_files = protectedFiles

        if protected {
            protected_files.insert(key)
        } else {
            protected_files.remove(key)
        }

        protectedFiles = protected_files
    }

    func clearProtection(for url: URL) {
        let key = url.lastPathComponent
        var protected_files = protectedFiles
        protected_files.remove(key)
        protectedFiles = protected_files
    }
}
