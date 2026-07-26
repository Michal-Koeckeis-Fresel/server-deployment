import Foundation
import AVFoundation

enum VideoCodec: String, CaseIterable {
    case hevc = "HEVC"
    case h264 = "H.264"

    var displayName: String {
        self.rawValue
    }

    var description: String {
        switch self {
        case .hevc:
            return "Modern codec, best compression (~40% smaller files)"
        case .h264:
            return "Compatible codec, larger files (~40% bigger)"
        }
    }

    var fileExtension: String {
        ".mov"
    }

    var fileType: AVFileType {
        switch self {
        case .hevc, .h264:
            return .mov
        }
    }

    var isAvailable: Bool {
        switch self {
        case .hevc:
            return true
        case .h264:
            return true
        }
    }

    var storageEstimate: String {
        switch self {
        case .hevc:
            return "~700-800 MB/min (both cameras)"
        case .h264:
            return "~1.2-1.4 GB/min (both cameras)"
        }
    }
}

class VideoCodecManager {
    static let shared = VideoCodecManager()
    private let codecPreferenceKey = "selectedVideoCodec"

    var selectedCodec: VideoCodec {
        get {
            if let saved = UserDefaults.standard.string(forKey: codecPreferenceKey),
               let codec = VideoCodec(rawValue: saved) {
                return codec
            }
            return .hevc
        }
        set {
            UserDefaults.standard.set(newValue.rawValue, forKey: codecPreferenceKey)
        }
    }

    func getVideoSettings() -> [String: Any] {
        let codecType: AVVideoCodecType
        switch selectedCodec {
        case .hevc:
            codecType = .hevc
        case .h264:
            codecType = .h264
        }

        return [
            AVVideoCodecKey: codecType,
            AVVideoWidthKey: 1920,
            AVVideoHeightKey: 1080,
            AVVideoCompressionPropertiesKey: [
                AVVideoAverageBitRateKey: 5_000_000,
                AVVideoProfileLevelKey: AVVideoProfileLevelH264HighAutoLevel
            ]
        ]
    }

    func estimateStorageSavings() -> (hevc: String, h264: String) {
        return (
            hevc: "~3.5-4 GB per 5-min chunk",
            h264: "~6-7 GB per 5-min chunk"
        )
    }
}
