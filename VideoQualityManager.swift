import Foundation

enum VideoQualityMode: String, CaseIterable {
    case standard = "Standard"
    case enhanced = "Enhanced (HDR + Advanced Stabilization)"
    case highQuality = "High Quality (Best for Clarity)"

    var description: String {
        switch self {
        case .standard:
            return "Standard recording with basic stabilization"
        case .enhanced:
            return "Enhanced with HDR video and cinematic stabilization"
        case .highQuality:
            return "Maximum clarity for evidence documentation"
        }
    }

    var displayName: String {
        self.rawValue
    }
}

class VideoQualityManager: ObservableObject {
    static let shared = VideoQualityManager()
    private let qualityModeKey = "selectedVideoQualityMode"
    private let lowLightBoostKey = "enableLowLightBoost"

    @Published var selectedQualityMode: VideoQualityMode {
        didSet {
            UserDefaults.standard.set(selectedQualityMode.rawValue, forKey: qualityModeKey)
        }
    }

    @Published var lowLightBoostEnabled: Bool {
        didSet {
            UserDefaults.standard.set(lowLightBoostEnabled, forKey: lowLightBoostKey)
        }
    }

    init() {
        if let saved = UserDefaults.standard.string(forKey: qualityModeKey),
           let mode = VideoQualityMode(rawValue: saved) {
            self.selectedQualityMode = mode
        } else {
            self.selectedQualityMode = .enhanced
        }

        self.lowLightBoostEnabled = UserDefaults.standard.bool(forKey: lowLightBoostKey)
        if !UserDefaults.standard.bool(forKey: lowLightBoostKey + "_initialized") {
            self.lowLightBoostEnabled = true
            UserDefaults.standard.set(true, forKey: lowLightBoostKey + "_initialized")
        }
    }

    var isHDREnabled: Bool {
        selectedQualityMode == .enhanced || selectedQualityMode == .highQuality
    }

    var isCinematicStabilizationEnabled: Bool {
        selectedQualityMode == .enhanced || selectedQualityMode == .highQuality
    }

    var storageMultiplier: Double {
        switch selectedQualityMode {
        case .standard:
            return 1.0
        case .enhanced:
            return 1.15
        case .highQuality:
            return 1.25
        }
    }

    var qualityDescription: String {
        switch selectedQualityMode {
        case .standard:
            return "🎥 Standard Quality\nBasic stabilization, standard codecs\nSmallest file size"
        case .enhanced:
            return "🎬 Enhanced Quality\nHDR video, cinematic stabilization\nBetter in low light\n~15% larger files"
        case .highQuality:
            return "📹 High Quality\nMaximum clarity for evidence\nBest stabilization\n~25% larger files"
        }
    }
}
