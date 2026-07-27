import AVFoundation

class MultiCameraSessionManager: NSObject {
    static let shared = MultiCameraSessionManager()

    private var multiCamSession: AVCaptureMultiCamSession?
    private var videoInputs: [CameraPosition: AVCaptureDeviceInput] = [:]
    private var audioInput: AVCaptureDeviceInput?
    private var movieFileOutputs: [CameraPosition: AVCaptureMovieFileOutput] = [:]
    private var videoDataOutputs: [CameraPosition: AVCaptureVideoDataOutput] = [:]
    private var audioDataOutputs: [CameraPosition: AVCaptureAudioDataOutput] = [:]

    private let sessionQueue = DispatchQueue(label: "com.dashcam.multicam.session", attributes: .concurrent)
    private let sessionStartedSemaphore = DispatchSemaphore(value: 0)

    var isRunning: Bool {
        multiCamSession?.isRunning ?? false
    }

    var hardwareCost: Float {
        multiCamSession?.hardwareCost ?? 0.0
    }

    func setupMultiCameraSession() -> Bool {
        print("[MultiCameraSession] ========== INITIALIZING MULTI-CAMERA SESSION ==========")

        let session = AVCaptureMultiCamSession()
        self.multiCamSession = session

        print("[MultiCameraSession] Created AVCaptureMultiCamSession")
        print("[MultiCameraSession] Initial hardware cost: \(String(format: "%.2f", hardwareCost))")

        // Note: AVCaptureMultiCamSession does NOT support session presets
        // Must configure activeFormat manually for each device
        print("[MultiCameraSession] ✅ MultiCamSession initialized (no presets - manual format configuration required)")

        return true
    }

    func addCamera(_ position: CameraPosition) throws {
        print("[MultiCameraSession] Adding camera: \(position.rawValue)")

        guard let session = multiCamSession else {
            print("[MultiCameraSession] ❌ MultiCamSession not initialized")
            throw CameraSetupError.invalidSession
        }

        // Find the video device
        let videoDevice = try findDevice(for: position)
        print("[MultiCameraSession] ✅ Found device: \(videoDevice.localizedName)")

        // Create and add video input
        let videoInput = try AVCaptureDeviceInput(device: videoDevice)
        if !session.canAddInput(videoInput) {
            print("[MultiCameraSession] ❌ Cannot add video input for \(position.rawValue)")
            throw CameraSetupError.inputCreationFailed
        }

        // Use addInputWithNoConnections for manual connection management
        session.addInputWithNoConnections(videoInput)
        self.videoInputs[position] = videoInput
        print("[MultiCameraSession] ✅ Video input added (no connections)")

        // Add audio input only once
        if audioInput == nil {
            let audioDevice = AVCaptureDevice.default(for: .audio)
            if let audioDevice = audioDevice {
                let audioInput = try AVCaptureDeviceInput(device: audioDevice)
                if session.canAddInput(audioInput) {
                    session.addInputWithNoConnections(audioInput)
                    self.audioInput = audioInput
                    print("[MultiCameraSession] ✅ Audio input added")
                } else {
                    print("[MultiCameraSession] ⚠️ Could not add audio input")
                }
            }
        }

        // Configure device format (since presets aren't available)
        try configureDeviceFormat(videoDevice)

        print("[MultiCameraSession] Hardware cost after adding \(position.rawValue): \(String(format: "%.2f", hardwareCost))")

        if hardwareCost >= 1.0 {
            print("[MultiCameraSession] ⚠️ WARNING: Hardware cost >= 1.0 - system may not support this configuration")
        }
    }

    func addMovieFileOutput(for position: CameraPosition) throws {
        print("[MultiCameraSession] Adding movie file output for: \(position.rawValue)")

        guard let session = multiCamSession else {
            throw CameraSetupError.invalidSession
        }

        guard let videoInput = videoInputs[position] else {
            print("[MultiCameraSession] ❌ No video input for \(position.rawValue)")
            throw CameraSetupError.inputCreationFailed
        }

        let movieOutput = AVCaptureMovieFileOutput()

        if !session.canAddOutput(movieOutput) {
            print("[MultiCameraSession] ❌ Cannot add movie output for \(position.rawValue)")
            throw CameraSetupError.outputCreationFailed
        }

        // Use addOutputWithNoConnections for manual connection management
        session.addOutputWithNoConnections(movieOutput)
        self.movieFileOutputs[position] = movieOutput
        print("[MultiCameraSession] ✅ Movie file output added (no connections)")

        // Manually connect video input to movie output
        let videoPort = videoInput.ports.first { $0.mediaType == .video }
        if let videoPort = videoPort {
            let connection = AVCaptureConnection(inputPorts: [videoPort], output: movieOutput)
            if session.canAddConnection(connection) {
                session.addConnection(connection)
                print("[MultiCameraSession] ✅ Video connection established for movie output")
            } else {
                print("[MultiCameraSession] ❌ Cannot add video connection for movie output")
                throw CameraSetupError.configurationFailed
            }
        }

        // Connect audio input if available
        if let audioInput = audioInput {
            let audioPort = audioInput.ports.first { $0.mediaType == .audio }
            if let audioPort = audioPort {
                let connection = AVCaptureConnection(inputPorts: [audioPort], output: movieOutput)
                if session.canAddConnection(connection) {
                    session.addConnection(connection)
                    print("[MultiCameraSession] ✅ Audio connection established for movie output")
                } else {
                    print("[MultiCameraSession] ⚠️ Could not add audio connection for movie output")
                }
            }
        }
    }

    func addVideoDataOutput(for position: CameraPosition, delegate: AVCaptureVideoDataOutputSampleBufferDelegate) throws {
        print("[MultiCameraSession] Adding video data output for: \(position.rawValue)")

        guard let session = multiCamSession else {
            throw CameraSetupError.invalidSession
        }

        guard let videoInput = videoInputs[position] else {
            print("[MultiCameraSession] ❌ No video input for \(position.rawValue)")
            throw CameraSetupError.inputCreationFailed
        }

        let videoDataOutput = AVCaptureVideoDataOutput()
        videoDataOutput.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA]
        videoDataOutput.alwaysDiscardsLateVideoFrames = true
        videoDataOutput.setSampleBufferDelegate(delegate, queue: sessionQueue)

        if !session.canAddOutput(videoDataOutput) {
            print("[MultiCameraSession] ❌ Cannot add video data output for \(position.rawValue)")
            throw CameraSetupError.outputCreationFailed
        }

        session.addOutputWithNoConnections(videoDataOutput)
        self.videoDataOutputs[position] = videoDataOutput
        print("[MultiCameraSession] ✅ Video data output added (no connections)")

        // Manually connect video input to data output
        let videoPort = videoInput.ports.first { $0.mediaType == .video }
        if let videoPort = videoPort {
            let connection = AVCaptureConnection(inputPorts: [videoPort], output: videoDataOutput)
            if session.canAddConnection(connection) {
                session.addConnection(connection)
                print("[MultiCameraSession] ✅ Video connection established for data output")
            } else {
                print("[MultiCameraSession] ❌ Cannot add video connection for data output")
                throw CameraSetupError.configurationFailed
            }
        }
    }

    func addAudioDataOutput(for position: CameraPosition, delegate: AVCaptureAudioDataOutputSampleBufferDelegate) throws {
        print("[MultiCameraSession] Adding audio data output for: \(position.rawValue)")

        guard let session = multiCamSession else {
            throw CameraSetupError.invalidSession
        }

        guard let audioInput = audioInput else {
            print("[MultiCameraSession] ⚠️ No audio input available")
            return
        }

        let audioDataOutput = AVCaptureAudioDataOutput()
        audioDataOutput.setSampleBufferDelegate(delegate, queue: sessionQueue)

        if !session.canAddOutput(audioDataOutput) {
            print("[MultiCameraSession] ❌ Cannot add audio data output")
            throw CameraSetupError.outputCreationFailed
        }

        session.addOutputWithNoConnections(audioDataOutput)
        self.audioDataOutputs[position] = audioDataOutput
        print("[MultiCameraSession] ✅ Audio data output added (no connections)")

        // Manually connect audio input to data output
        let audioPort = audioInput.ports.first { $0.mediaType == .audio }
        if let audioPort = audioPort {
            let connection = AVCaptureConnection(inputPorts: [audioPort], output: audioDataOutput)
            if session.canAddConnection(connection) {
                session.addConnection(connection)
                print("[MultiCameraSession] ✅ Audio connection established for data output")
            } else {
                print("[MultiCameraSession] ❌ Cannot add audio connection for data output")
                throw CameraSetupError.configurationFailed
            }
        }
    }

    func startSession() {
        print("[MultiCameraSession] ========== STARTING MULTI-CAMERA SESSION ==========")
        print("[MultiCameraSession] Cameras configured: \(videoInputs.keys.map { $0.rawValue }.joined(separator: ", "))")
        print("[MultiCameraSession] Final hardware cost: \(String(format: "%.2f", hardwareCost))")

        guard let session = multiCamSession else {
            print("[MultiCameraSession] ❌ Session not initialized")
            return
        }

        sessionQueue.async {
            print("[MultiCameraSession] Starting session on background queue...")
            session.startRunning()
            print("[MultiCameraSession] ✅ Session running: \(session.isRunning)")
            self.sessionStartedSemaphore.signal()
        }
    }

    func stopSession() {
        print("[MultiCameraSession] ========== STOPPING MULTI-CAMERA SESSION ==========")

        guard let session = multiCamSession else {
            return
        }

        sessionQueue.async(flags: .barrier) {
            session.stopRunning()
            print("[MultiCameraSession] ✅ Session stopped")
        }
    }

    func getMovieFileOutput(for position: CameraPosition) -> AVCaptureMovieFileOutput? {
        movieFileOutputs[position]
    }

    func getVideoDataOutput(for position: CameraPosition) -> AVCaptureVideoDataOutput? {
        videoDataOutputs[position]
    }

    func getAudioDataOutput(for position: CameraPosition) -> AVCaptureAudioDataOutput? {
        audioDataOutputs[position]
    }

    // MARK: - Private Helpers

    private func findDevice(for position: CameraPosition) throws -> AVCaptureDevice {
        print("[MultiCameraSession] Looking for \(position.rawValue) - deviceType: \(position.deviceType), position: \(position.position)")

        guard let device = AVCaptureDevice.default(position.deviceType, for: .video, position: position.position) else {
            // Fallback for devices that might not have the exact device type
            if let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: position.position) {
                print("[MultiCameraSession] ✅ Found fallback device: \(device.localizedName)")
                return device
            }
            print("[MultiCameraSession] ❌ Device not found for \(position.rawValue)")
            throw CameraSetupError.deviceNotAvailable
        }

        print("[MultiCameraSession] ✅ Found device: \(device.localizedName)")
        return device
    }

    private func configureDeviceFormat(_ device: AVCaptureDevice) throws {
        print("[MultiCameraSession] Configuring format for: \(device.localizedName)")

        // Find a suitable format for 1920x1080 at 30fps
        guard let format = device.formats.first(where: { format in
            let formatDesc = format.formatDescription
            let dimensions = CMVideoFormatDescriptionGetDimensions(formatDesc)
            return dimensions.width == 1920 && dimensions.height == 1080
        }) else {
            print("[MultiCameraSession] ⚠️ Could not find 1920x1080 format, using device default")
            return
        }

        try device.lockForConfiguration()
        device.activeFormat = format

        // Set frame rate to 30fps
        let frameDuration = CMTimeMake(value: 1, timescale: 30)
        device.activeVideoMinFrameDuration = frameDuration
        device.activeVideoMaxFrameDuration = frameDuration

        device.unlockForConfiguration()
        print("[MultiCameraSession] ✅ Format configured: 1920x1080 @ 30fps")
    }
}
