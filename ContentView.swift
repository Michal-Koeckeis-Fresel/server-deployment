import SwiftUI

struct ContentView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel
    @StateObject private var permissionManager = PermissionStatusManager()
    @StateObject private var batteryManager = BatteryMonitorManager.shared
    @StateObject private var locationManager = LocationManager.shared
    @StateObject private var parkingManager = ParkingModeManager.shared
    @StateObject private var autoStartManager = AutoStartRecordingManager.shared
    @StateObject private var siriManager = SiriShortcutManager.shared
    @StateObject private var gForceMonitor = GForceMonitor.shared
    @StateObject private var performanceLogger = PerformanceLogger.shared
    @State private var cameraSetup = false
    @State private var showSettings = false
    @State private var showFiles = false
    @State private var showPiP = false
    @State private var showMultiCameraPreview = false
    @State private var recordingStartTime = Date()

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()

                VStack(spacing: 24) {
                    // Header with buttons
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Dashcam")
                                .font(.system(size: 32, weight: .bold))
                                .foregroundColor(.white)

                            Text(viewModel.isRecording ? "Recording..." : "Ready")
                                .font(.subheadline)
                                .foregroundColor(viewModel.isRecording ? .red : .gray)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)

                        VStack(spacing: 8) {
                            NavigationLink(destination: LiveCameraFeedView()) {
                                Image(systemName: "video.fill")
                                    .font(.system(size: 18))
                                    .frame(width: 44, height: 44)
                                    .background(Color.gray.opacity(0.3))
                                    .foregroundColor(.white)
                                    .cornerRadius(8)
                            }

                            NavigationLink(destination: MultiCameraPreviewView()) {
                                Image(systemName: "square.grid.2x2")
                                    .font(.system(size: 18))
                                    .frame(width: 44, height: 44)
                                    .background(Color.gray.opacity(0.3))
                                    .foregroundColor(.white)
                                    .cornerRadius(8)
                            }

                            Button(action: { showPiP.toggle() }) {
                                Image(systemName: "pip.fill")
                                    .font(.system(size: 18))
                                    .frame(width: 44, height: 44)
                                    .background(showPiP ? Color.blue.opacity(0.6) : Color.gray.opacity(0.3))
                                    .foregroundColor(.white)
                                    .cornerRadius(8)
                            }

                            NavigationLink(destination: SettingsView()) {
                                Image(systemName: "gear")
                                    .font(.system(size: 18))
                                    .frame(width: 44, height: 44)
                                    .background(Color.gray.opacity(0.3))
                                    .foregroundColor(.white)
                                    .cornerRadius(8)
                            }

                            NavigationLink(destination: FilesView()) {
                                Image(systemName: "film.stack")
                                    .font(.system(size: 18))
                                    .frame(width: 44, height: 44)
                                    .background(Color.gray.opacity(0.3))
                                    .foregroundColor(.white)
                                    .cornerRadius(8)
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.top, 16)

                // Siri Status Indicator
                HStack(spacing: 8) {
                    Image(systemName: "mic.circle.fill")
                        .foregroundColor(.blue)
                    Text("Siri commands enabled")
                        .font(.caption2)
                        .foregroundColor(.blue)
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(Color.blue.opacity(0.05))
                .cornerRadius(6)

                // Low Power Mode Warning
                let powerModeMonitor = LowPowerModeMonitor.shared
                if powerModeMonitor.isLowPowerModeEnabled {
                    HStack(spacing: 12) {
                        Image(systemName: "bolt.slash.fill")
                            .foregroundColor(.orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Low Power Mode")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(.orange)
                            Text("Video quality reduced to conserve battery")
                                .font(.caption2)
                                .foregroundColor(.orange)
                        }
                        Spacer()
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(Color.orange.opacity(0.1))
                    .cornerRadius(8)
                }

                // Thermal Warning
                if let thermalMessage = viewModel.thermalWarningMessage {
                    HStack(spacing: 12) {
                        Image(systemName: "thermometer.sun.fill")
                            .foregroundColor(.red)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Thermal Alert")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(.red)
                            Text(thermalMessage)
                                .font(.caption2)
                                .foregroundColor(.red)
                        }
                        Spacer()
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(Color.red.opacity(0.1))
                    .cornerRadius(8)
                }

                // Battery Warning
                if batteryManager.shouldShowLowBatteryWarning {
                    HStack(spacing: 12) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Low Battery")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(.orange)
                            Text("\(batteryManager.batteryPercentage) remaining - Consider charging")
                                .font(.caption2)
                                .foregroundColor(.orange)
                        }
                        Spacer()
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(Color.orange.opacity(0.1))
                    .cornerRadius(8)
                }

                if batteryManager.shouldStopRecording {
                    HStack(spacing: 12) {
                        Image(systemName: "exclamationmark.circle.fill")
                            .foregroundColor(.red)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Critical Battery")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(.red)
                            Text("\(batteryManager.batteryPercentage) - Please charge immediately!")
                                .font(.caption2)
                                .foregroundColor(.red)
                        }
                        Spacer()
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(Color.red.opacity(0.1))
                    .cornerRadius(8)
                }

                // Permission Warning
                if !permissionManager.allPermissionsGranted() {
                    HStack(spacing: 12) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Permissions Required")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(.orange)
                            Text("Camera and Microphone needed for recording")
                                .font(.caption2)
                                .foregroundColor(.orange)
                        }
                        Spacer()
                        NavigationLink(destination: SettingsView()) {
                            Image(systemName: "chevron.right")
                                .foregroundColor(.orange)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(Color.orange.opacity(0.1))
                    .cornerRadius(8)
                }

                // Parking Mode Status
                if parkingManager.isParkingModeEnabled {
                    HStack(spacing: 12) {
                        Image(systemName: parkingManager.isParked ? "parkingsign.circle.fill" : "car.fill")
                            .foregroundColor(parkingManager.isParked ? .purple : .gray)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Parking Mode")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(parkingManager.isParked ? .purple : .gray)
                            Text(parkingManager.parkingStatusDescription)
                                .font(.caption2)
                                .foregroundColor(parkingManager.isParked ? .purple : .gray)
                        }
                        Spacer()
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(parkingManager.isParked ? Color.purple.opacity(0.1) : Color.gray.opacity(0.05))
                    .cornerRadius(8)
                }

                // Auto-Start Status
                if autoStartManager.isAutoStartEnabled && autoStartManager.isDriving {
                    HStack(spacing: 12) {
                        Image(systemName: "play.circle.fill")
                            .foregroundColor(.green)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Auto-Start Ready")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(.green)
                            Text("Driving detected - will start recording automatically")
                                .font(.caption2)
                                .foregroundColor(.green)
                        }
                        Spacer()
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(Color.green.opacity(0.1))
                    .cornerRadius(8)
                }

                // Camera Status Display
                VStack(spacing: 8) {
                    Text("Cameras")
                        .font(.caption)
                        .foregroundColor(.gray)
                        .frame(maxWidth: .infinity, alignment: .leading)

                    VStack(spacing: 6) {
                        ForEach(CameraPosition.allCases, id: \.self) { position in
                            HStack(spacing: 10) {
                                let status = viewModel.cameraStatus[position] ?? "Unknown"
                                let isRecording = status == "Recording"

                                Circle()
                                    .fill(
                                        status == "Ready" ? Color.green :
                                        status == "Recording" ? Color.red :
                                        Color.gray
                                    )
                                    .frame(width: 8, height: 8)

                                Text(position.rawValue)
                                    .font(.caption)
                                    .foregroundColor(.white)

                                Spacer()

                                Text(status)
                                    .font(.caption2)
                                    .foregroundColor(.gray)
                            }
                        }
                    }
                    .padding(10)
                    .background(Color.gray.opacity(0.05))
                    .cornerRadius(6)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 12)
                .background(Color.gray.opacity(0.1))
                .cornerRadius(8)

                // Storage Display
                VStack(spacing: 8) {
                    HStack(spacing: 12) {
                        Image(systemName: "internaldrive.fill")
                            .foregroundColor(.blue)
                        Text("Storage")
                            .font(.subheadline)
                            .foregroundColor(.gray)
                        Spacer()
                        Text(String(format: "%.2f GB / %.0f GB", viewModel.currentStorageGB, viewModel.maxStorageGB))
                            .font(.subheadline)
                            .foregroundColor(.white)
                            .fontWeight(.semibold)
                    }
                    ProgressView(value: min(viewModel.currentStorageGB / viewModel.maxStorageGB, 1.0))
                        .tint(.blue)
                }
                .padding(12)
                .background(Color.gray.opacity(0.1))
                .cornerRadius(8)

                // G-Force Display
                if viewModel.isRecording {
                    VStack(spacing: 12) {
                        HStack(spacing: 12) {
                            Image(systemName: "waveform.circle.fill")
                                .foregroundColor(.orange)
                            Text("G-Force Monitoring")
                                .font(.subheadline)
                                .foregroundColor(.gray)
                            Spacer()
                        }

                        VStack(spacing: 8) {
                            HStack(spacing: 20) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Current")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Text(gForceMonitor.getGForceString())
                                        .font(.headline)
                                        .foregroundColor(.white)
                                        .fontWeight(.semibold)
                                }

                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Peak")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Text(gForceMonitor.getPeakGForceString())
                                        .font(.headline)
                                        .foregroundColor(.orange)
                                        .fontWeight(.semibold)
                                }

                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Average")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Text(gForceMonitor.getAverageGForceString())
                                        .font(.headline)
                                        .foregroundColor(.white)
                                        .fontWeight(.semibold)
                                }

                                Spacer()
                            }
                        }
                        .padding(10)
                        .background(Color.orange.opacity(0.05))
                        .cornerRadius(6)
                    }
                    .padding(12)
                    .background(Color.gray.opacity(0.1))
                    .cornerRadius(8)
                }

                // Performance Metrics Display
                if viewModel.isRecording {
                    VStack(spacing: 12) {
                        HStack(spacing: 12) {
                            Image(systemName: "chart.line.uptrend.xyaxis")
                                .foregroundColor(.green)
                            Text("Performance Metrics")
                                .font(.subheadline)
                                .foregroundColor(.gray)
                            Spacer()
                        }

                        VStack(spacing: 8) {
                            HStack(spacing: 20) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("FPS")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Text(String(format: "%.1f", performanceLogger.recordingFPS))
                                        .font(.headline)
                                        .foregroundColor(.white)
                                        .fontWeight(.semibold)
                                }

                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Memory")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Text(String(format: "%.0f MB", performanceLogger.memoryUsageMB))
                                        .font(.headline)
                                        .foregroundColor(.white)
                                        .fontWeight(.semibold)
                                }

                                VStack(alignment: .leading, spacing: 4) {
                                    Text("CPU")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Text(String(format: "%.1f%%", performanceLogger.cpuUsagePercent))
                                        .font(.headline)
                                        .foregroundColor(.white)
                                        .fontWeight(.semibold)
                                }

                                Spacer()
                            }
                        }
                        .padding(10)
                        .background(Color.green.opacity(0.05))
                        .cornerRadius(6)
                    }
                    .padding(12)
                    .background(Color.gray.opacity(0.1))
                    .cornerRadius(8)
                }

                    // Impact Detection Status
                    if viewModel.isRecording {
                        if viewModel.isSlowMotionActive {
                            HStack(spacing: 12) {
                                Image(systemName: "slowmo")
                                    .foregroundColor(.purple)
                                    .animation(.easeInOut(duration: 0.3), value: viewModel.isSlowMotionActive)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Slow-Motion Recording")
                                        .font(.caption)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.purple)
                                    Text("Capturing at 60 fps for impact details")
                                        .font(.caption2)
                                        .foregroundColor(.purple)
                                }
                                Spacer()
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.purple.opacity(0.1))
                            .cornerRadius(6)
                        } else if viewModel.crashDetected || viewModel.emergencyBrakeDetected {
                            VStack(spacing: 8) {
                                if viewModel.crashDetected {
                                    HStack(spacing: 12) {
                                        Image(systemName: "exclamationmark.triangle.fill")
                                            .foregroundColor(.red)
                                            .animation(.easeInOut(duration: 0.5), value: viewModel.crashDetected)
                                        Text("Crash Detected - Recording Protected")
                                            .font(.caption)
                                            .foregroundColor(.red)
                                        Spacer()
                                    }
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 8)
                                    .background(Color.red.opacity(0.1))
                                    .cornerRadius(6)
                                }

                                if viewModel.emergencyBrakeDetected {
                                    HStack(spacing: 12) {
                                        Image(systemName: "bolt.fill")
                                            .foregroundColor(.orange)
                                            .animation(.easeInOut(duration: 0.5), value: viewModel.emergencyBrakeDetected)
                                        Text("Emergency Brake - Recording Protected")
                                            .font(.caption)
                                            .foregroundColor(.orange)
                                        Spacer()
                                    }
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 8)
                                    .background(Color.orange.opacity(0.1))
                                    .cornerRadius(6)
                                }
                            }
                        } else {
                            HStack(spacing: 12) {
                                Circle()
                                    .fill(Color.green)
                                    .frame(width: 8, height: 8)
                                Text("Impact Detection Active")
                                    .font(.caption)
                                    .foregroundColor(.green)
                                Spacer()
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.green.opacity(0.1))
                            .cornerRadius(6)
                        }
                    }
                }

                Spacer()

                // Timer Display
                VStack(spacing: 12) {
                    if viewModel.isRecording {
                        HStack(spacing: 12) {
                            Circle()
                                .fill(Color.red)
                                .frame(width: 16, height: 16)
                                .opacity(0.7)

                            VStack(alignment: .leading, spacing: 2) {
                                Text("Recording Chunk \(viewModel.currentChunkNumber)")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Text("Tap lock to protect current recording")
                                    .font(.caption2)
                                    .foregroundColor(.gray)
                            }

                            Spacer()

                            Text(viewModel.recordingTime)
                                .font(.system(.title, design: .monospaced))
                                .foregroundColor(.white)
                                .fontWeight(.semibold)
                        }
                        .padding(.horizontal, 20)
                        .padding(.vertical, 16)
                        .background(Color.red.opacity(0.15))
                        .cornerRadius(12)
                    } else {
                        Text("Tap Record to Start")
                            .font(.headline)
                            .foregroundColor(.gray)
                    }
                }

                Spacer()

                // Control Buttons
                VStack(spacing: 12) {
                    if !viewModel.isRecording {
                        Button(action: {
                            if !cameraSetup {
                                viewModel.setupCamera()
                                cameraSetup = true
                            }
                            viewModel.startRecording()
                        }) {
                            HStack(spacing: 12) {
                                Image(systemName: "record.circle.fill")
                                    .font(.system(size: 24))

                                Text("Start Recording")
                                    .font(.headline)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 16)
                            .foregroundColor(.white)
                            .background(Color.red)
                            .cornerRadius(12)
                        }
                    } else {
                        VStack(spacing: 10) {
                            Button(action: {
                                viewModel.stopRecording()
                            }) {
                                HStack(spacing: 12) {
                                    Image(systemName: "stop.circle.fill")
                                        .font(.system(size: 24))

                                    Text("Stop Recording")
                                        .font(.headline)
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 16)
                                .foregroundColor(.white)
                                .background(Color.orange)
                                .cornerRadius(12)
                            }

                            Button(action: {
                                viewModel.protectCurrentChunk()
                            }) {
                                HStack(spacing: 12) {
                                    Image(systemName: "lock.circle.fill")
                                        .font(.system(size: 24))

                                    Text("Protect Recording")
                                        .font(.headline)
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 16)
                                .foregroundColor(.white)
                                .background(Color.blue)
                                .cornerRadius(12)
                            }
                        }
                    }

                    // Error Display
                    if let error = viewModel.errorMessage {
                        HStack(spacing: 8) {
                            Image(systemName: "exclamationmark.circle.fill")
                                .foregroundColor(.red)

                            Text(error)
                                .font(.caption)
                                .foregroundColor(.red)

                            Spacer()
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(8)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 32)

                if showPiP {
                    PiPCameraView()
                        .environmentObject(viewModel)
                        .transition(.scale)
                }

                // Watermark overlay with FPS, GPS and recording info
                if viewModel.isRecording {
                    WatermarkView(
                        fpsCounter: viewModel.fpsCounter,
                        batteryManager: batteryManager,
                        locationManager: locationManager,
                        timestamp: recordingStartTime
                    )
                    .transition(.fadeIn)
                }
            }
        }
            .navigationBarHidden(true)
            .onChange(of: viewModel.isRecording) { newValue in
                if newValue {
                    recordingStartTime = Date()
                }
            }
        }
        .alert(
            viewModel.crashDetected ? "⚠️ Crash Detected" : "🛑 Emergency Brake Detected",
            isPresented: $viewModel.showCrashAlert
        ) {
            Button("OK", role: .cancel) { }
        } message: {
            if viewModel.crashDetected {
                Text("A potential collision was detected. The current recording has been automatically protected from deletion.")
            } else {
                Text("An emergency braking event was detected. The current recording has been automatically protected from deletion.")
            }
        }
        .onAppear {
            if !cameraSetup {
                viewModel.setupCameras()
                cameraSetup = true
            }
            permissionManager.updatePermissionStatuses()
            locationManager.requestLocationPermission()

            if parkingManager.isParkingModeEnabled {
                parkingManager.startParkingModeMonitoring()
            }

            siriManager.registerSiriVoiceShortcuts()
        }
        .onDisappear {
            parkingManager.stopParkingModeMonitoring()
        }
        .onChange(of: parkingManager.isParkingModeEnabled) { newValue in
            if newValue {
                parkingManager.startParkingModeMonitoring()
            } else {
                parkingManager.stopParkingModeMonitoring()
            }
        }
        .onChange(of: parkingManager.parkingMotionDetected) { motionDetected in
            if motionDetected && parkingManager.isParked {
                for (_, url) in viewModel.chunkURLs {
                    viewModel.fileProtectionManager.setProtection(true, for: url)
                }
                viewModel.errorMessage = "🚨 Motion detected while parked - recordings protected"
                DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                    viewModel.errorMessage = nil
                }
            }
        }
        .onChange(of: autoStartManager.isDriving) { isDriving in
            if isDriving && autoStartManager.isAutoStartEnabled && !viewModel.isRecording {
                if !cameraSetup {
                    viewModel.setupCameras()
                    cameraSetup = true
                }
                viewModel.startRecording()
            }
        }
        .onChange(of: siriManager.lastCommand) { command in
            if let command = command {
                siriManager.handleShortcutCommand(command, viewModel: viewModel)
            }
        }
        .onReceive(
            NotificationCenter.default.publisher(for: UIApplication.willEnterForegroundNotification),
            perform: { _ in
                permissionManager.updatePermissionStatuses()
            }
        )
    }
}

#Preview {
    ContentView()
        .environmentObject(CameraDashcamViewModel())
}
