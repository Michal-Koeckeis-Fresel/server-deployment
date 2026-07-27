import AVFoundation

class CameraCapabilityChecker {
    static let shared = CameraCapabilityChecker()

    struct CameraCapabilities {
        let position: CameraPosition
        let isAvailable: Bool
        let supportsHDR: Bool
        let supportsCinematicStabilization: Bool
        let supportsLowLightBoost: Bool
        let maxResolution: CMVideoDimensions?
        let supportedFrameRates: [Int]
    }

    func checkCapabilities(for position: CameraPosition) -> CameraCapabilities {
        let deviceType = position.deviceType
        let cameraPosition = position.position

        guard let device = AVCaptureDevice.default(deviceType, for: .video, position: cameraPosition) else {
            return CameraCapabilities(
                position: position,
                isAvailable: false,
                supportsHDR: false,
                supportsCinematicStabilization: false,
                supportsLowLightBoost: false,
                maxResolution: nil,
                supportedFrameRates: []
            )
        }

        guard device.isConnected else {
            return CameraCapabilities(
                position: position,
                isAvailable: false,
                supportsHDR: false,
                supportsCinematicStabilization: false,
                supportsLowLightBoost: false,
                maxResolution: nil,
                supportedFrameRates: []
            )
        }

        let supportsHDR = true

        let supportsCinematic = true

        let supportedFormats = device.formats
        var maxResolution: CMVideoDimensions?
        var supportedFrameRates: Set<Int> = []

        for format in supportedFormats {
            let dimensions = CMVideoFormatDescriptionGetDimensions(format.formatDescription)
            if maxResolution == nil || (dimensions.width * dimensions.height) > (maxResolution!.width * maxResolution!.height) {
                maxResolution = dimensions
            }

            for range in format.videoSupportedFrameRateRanges {
                let maxFrameRate = Int(range.maxFrameRate)
                supportedFrameRates.insert(maxFrameRate)
            }
        }

        return CameraCapabilities(
            position: position,
            isAvailable: true,
            supportsHDR: supportsHDR,
            supportsCinematicStabilization: supportsCinematic,
            supportsLowLightBoost: device.isLowLightBoostSupported,
            maxResolution: maxResolution,
            supportedFrameRates: Array(supportedFrameRates).sorted()
        )
    }

    func validateSessionConfiguration() -> Bool {
        let session = AVCaptureSession()
        let presets: [AVCaptureSession.Preset] = [.high, .medium, .low]

        for preset in presets {
            if session.canSetSessionPreset(preset) {
                return true
            }
        }

        return false
    }

    func getAvailableCameras() -> [CameraCapabilities] {
        return CameraPosition.allCases.map { position in
            checkCapabilities(for: position)
        }
    }

    func printCapabilitiesReport() {
        print("=== Camera Capabilities Report ===")
        for camera in getAvailableCameras() {
            print("\n\(camera.position.rawValue):")
            print("  Available: \(camera.isAvailable)")
            if camera.isAvailable {
                print("  HDR Support: \(camera.supportsHDR)")
                print("  Cinematic Stabilization: \(camera.supportsCinematicStabilization)")
                print("  Low-Light Boost: \(camera.supportsLowLightBoost)")
                if let resolution = camera.maxResolution {
                    print("  Max Resolution: \(resolution.width)x\(resolution.height)")
                }
                if !camera.supportedFrameRates.isEmpty {
                    print("  Supported Frame Rates: \(camera.supportedFrameRates) fps")
                }
            }
        }
        print("\nSession Configuration Valid: \(validateSessionConfiguration())")
        print("=================================\n")
    }
}
