import SwiftUI

enum AppearanceMode: String, CaseIterable {
    case light = "Light"
    case dark = "Dark"
    case system = "System"

    var description: String {
        switch self {
        case .light:
            return "Always use light theme"
        case .dark:
            return "Always use dark theme"
        case .system:
            return "Follow system settings"
        }
    }

    var colorScheme: ColorScheme? {
        switch self {
        case .light:
            return .light
        case .dark:
            return .dark
        case .system:
            return nil
        }
    }

    var icon: String {
        switch self {
        case .light:
            return "sun.max.fill"
        case .dark:
            return "moon.stars.fill"
        case .system:
            return "gear"
        }
    }
}

class AppearanceManager: NSObject, ObservableObject {
    static let shared = AppearanceManager()

    @Published var selectedMode: AppearanceMode {
        didSet {
            UserDefaults.standard.set(selectedMode.rawValue, forKey: "appearanceMode")
        }
    }

    override init() {
        let saved = UserDefaults.standard.string(forKey: "appearanceMode") ?? "system"
        self.selectedMode = AppearanceMode(rawValue: saved) ?? .system
        super.init()
    }

    var currentColorScheme: ColorScheme? {
        selectedMode.colorScheme
    }
}
