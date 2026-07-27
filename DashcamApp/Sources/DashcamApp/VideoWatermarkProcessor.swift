import AVFoundation
import UIKit

class VideoWatermarkProcessor {
    static func addWatermark(to inputURL: URL, output outputURL: URL, metadata: WatermarkMetadata, completion: @escaping (Bool, Error?) -> Void) {
        let asset = AVURLAsset(url: inputURL)

        Task {
            do {
                let videoTracks = try await asset.loadTracks(withMediaType: .video)
                guard let videoTrack = videoTracks.first else {
                    completion(false, NSError(domain: "VideoWatermarkProcessor", code: -1, userInfo: [NSLocalizedDescriptionKey: "No video track found"]))
                    return
                }

                let composition = AVMutableComposition()
                guard let compositionVideoTrack = composition.addMutableTrack(withMediaType: .video, preferredTrackID: kCMPersistentTrackID_Invalid) else {
                    completion(false, NSError(domain: "VideoWatermarkProcessor", code: -2, userInfo: [NSLocalizedDescriptionKey: "Cannot create composition track"]))
                    return
                }

                let duration = try await asset.load(.duration)
                try compositionVideoTrack.insertTimeRange(CMTimeRangeMake(start: .zero, duration: duration), of: videoTrack, at: .zero)

                let audioTracks = try await asset.loadTracks(withMediaType: .audio)
                if let audioTrack = audioTracks.first {
                    if let compositionAudioTrack = composition.addMutableTrack(withMediaType: .audio, preferredTrackID: kCMPersistentTrackID_Invalid) {
                        try compositionAudioTrack.insertTimeRange(CMTimeRangeMake(start: .zero, duration: duration), of: audioTrack, at: .zero)
                    }
                }

                let videoComposition = try await createVideoComposition(for: compositionVideoTrack, metadata: metadata, videoTrack: videoTrack, assetDuration: duration)

                try FileManager.default.removeItem(at: outputURL)

                guard let exporter = AVAssetExportSession(asset: composition, presetName: AVAssetExportPreset1920x1080) else {
                    completion(false, NSError(domain: "VideoWatermarkProcessor", code: -3, userInfo: [NSLocalizedDescriptionKey: "Cannot create exporter"]))
                    return
                }
                exporter.videoComposition = videoComposition
                exporter.outputFileType = .mov
                exporter.outputURL = outputURL

                exporter.exportAsynchronously {
                    DispatchQueue.main.async {
                        if exporter.status == .completed {
                            completion(true, nil)
                        } else {
                            let error = NSError(domain: "VideoWatermarkProcessor", code: Int(exporter.status.rawValue), userInfo: [NSLocalizedDescriptionKey: "Export failed: \(exporter.status)"])
                            completion(false, error)
                        }
                    }
                }
            } catch {
                completion(false, error)
            }
        }
    }

    private static func createVideoComposition(for track: AVMutableCompositionTrack, metadata: WatermarkMetadata, videoTrack: AVAssetTrack, assetDuration: CMTime) async throws -> AVVideoComposition {
        let videoComposition = AVMutableVideoComposition()
        videoComposition.frameDuration = CMTimeMake(value: 1, timescale: 30)

        let size = try await videoTrack.load(.naturalSize)
        videoComposition.renderSize = size

        let instruction = AVMutableVideoCompositionInstruction()
        instruction.timeRange = CMTimeRangeMake(start: .zero, duration: assetDuration)

        let layerInstruction = AVMutableVideoCompositionLayerInstruction(assetTrack: track)
        instruction.layerInstructions = [layerInstruction]

        let parentLayer = CALayer()
        parentLayer.frame = CGRect(x: 0, y: 0, width: size.width, height: size.height)

        let videoLayer = CALayer()
        videoLayer.frame = parentLayer.frame

        let watermarkLayer = createWatermarkLayer(size: size, metadata: metadata)
        parentLayer.addSublayer(videoLayer)
        parentLayer.addSublayer(watermarkLayer)

        videoComposition.instructions = [instruction]
        videoComposition.animationTool = AVVideoCompositionCoreAnimationTool(postProcessingAsVideoLayer: videoLayer, in: parentLayer)

        return videoComposition
    }

    private static func createWatermarkLayer(size: CGSize, metadata: WatermarkMetadata) -> CALayer {
        let watermarkLayer = CALayer()
        watermarkLayer.frame = CGRect(x: 0, y: 0, width: size.width, height: size.height)

        // Create top info layer
        let topLayer = createTopInfoLayer(size: size, metadata: metadata)
        watermarkLayer.addSublayer(topLayer)

        // Create bottom GPS layer if location available
        if let location = metadata.location {
            let bottomLayer = createBottomGPSLayer(size: size, metadata: metadata, location: location)
            watermarkLayer.addSublayer(bottomLayer)
        }

        return watermarkLayer
    }

    private static func createTopInfoLayer(size: CGSize, metadata: WatermarkMetadata) -> CALayer {
        let layer = CALayer()
        layer.frame = CGRect(x: 0, y: 0, width: size.width, height: 60)

        let textLayer = CATextLayer()
        textLayer.string = "FPS: \(metadata.fps) | \(metadata.timestamp) | Battery: \(metadata.battery)%"
        textLayer.font = UIFont.monospacedSystemFont(ofSize: 24, weight: .semibold)
        textLayer.foregroundColor = UIColor.white.cgColor
        textLayer.frame = CGRect(x: 20, y: 10, width: size.width - 40, height: 40)
        textLayer.shadowOpacity = 0.8
        textLayer.shadowColor = UIColor.black.cgColor
        textLayer.shadowOffset = CGSize(width: 1, height: 1)
        textLayer.shadowRadius = 2

        layer.addSublayer(textLayer)
        return layer
    }

    private static func createBottomGPSLayer(size: CGSize, metadata: WatermarkMetadata, location: (lat: Double, lon: Double, speed: Double, altitude: Double, heading: Double)) -> CALayer {
        let layer = CALayer()
        let layerHeight: CGFloat = 80
        layer.frame = CGRect(x: 0, y: size.height - layerHeight, width: size.width, height: layerHeight)

        let gpsText = String(format: "GPS: %.4f°N, %.4f°E | Speed: %.0f km/h | Alt: %.0f m | Heading: %.0f°",
                           location.lat, location.lon, location.speed, location.altitude, location.heading)

        let textLayer = CATextLayer()
        textLayer.string = gpsText
        textLayer.font = UIFont.monospacedSystemFont(ofSize: 20, weight: .regular)
        textLayer.foregroundColor = UIColor.white.cgColor
        textLayer.frame = CGRect(x: 20, y: 20, width: size.width - 40, height: 40)
        textLayer.shadowOpacity = 0.8
        textLayer.shadowColor = UIColor.black.cgColor
        textLayer.shadowOffset = CGSize(width: 1, height: 1)
        textLayer.shadowRadius = 2

        layer.addSublayer(textLayer)
        return layer
    }
}

struct WatermarkMetadata {
    let fps: Int
    let timestamp: String
    let battery: Int
    let location: (lat: Double, lon: Double, speed: Double, altitude: Double, heading: Double)?

    init(fps: Int, timestamp: Date, batteryLevel: Float, location: (lat: Double, lon: Double, speed: Double, altitude: Double, heading: Double)? = nil) {
        self.fps = fps
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        self.timestamp = formatter.string(from: timestamp)
        self.battery = Int(batteryLevel * 100)
        self.location = location
    }
}
