import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel
    @Environment(\.dismiss) var dismiss
    @StateObject private var qualityManager = VideoQualityManager.shared
    @StateObject private var gForceMonitor = GForceMonitor.shared
    @StateObject private var performanceLogger = PerformanceLogger.shared
    @StateObject private var nightModeManager = NightModeManager.shared
    @State private var selectedStorageLocation = StorageLocationManager.shared.selectedLocation
    @State private var selectedCodec = VideoCodecManager.shared.selectedCodec
    @State private var showMigrationAlert = false
    @State private var migrationMessage = ""
    private let storageManager = StorageManager()

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            VStack(spacing: 0) {
                // Header
                HStack {
                    Button(action: { dismiss() }) {
                        HStack(spacing: 6) {
                            Image(systemName: "chevron.left")
                            Text("Back")
                        }
                        .foregroundColor(.blue)
                    }
                    Spacer()
                    Text("Settings")
                        .font(.headline)
                        .foregroundColor(.white)
                    Spacer()
                    Color.clear.frame(width: 44)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 16)
                .borderBottom(Color.gray.opacity(0.2))

                ScrollView {
                    VStack(spacing: 24) {
                        // Performance Dashboard Quick Access
                        NavigationLink(destination: PerformanceDashboardView()) {
                            HStack(spacing: 12) {
                                Image(systemName: "chart.line.uptrend.xyaxis")
                                    .foregroundColor(.green)
                                    .font(.system(size: 18))

                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Performance Dashboard")
                                        .font(.subheadline)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.white)
                                    Text("View detailed metrics and analytics")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                }

                                Spacer()

                                Image(systemName: "chevron.right")
                                    .foregroundColor(.gray)
                            }
                            .padding(16)
                            .background(Color.gray.opacity(0.1))
                            .cornerRadius(12)
                        }

                        // Appearance Settings
                        AppearanceView()

                        // Battery Status
                        BatteryStatusView()

                        // Low Power Mode Status
                        LowPowerModeView()

                        // System Pressure Status
                        SystemPressureView()

                        // G-Force Monitoring Status
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("G-Force Monitoring", systemImage: "waveform.circle.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                            }

                            VStack(spacing: 10) {
                                HStack {
                                    Text("Status")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Spacer()
                                    Text("Active during recording")
                                        .font(.caption)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.green)
                                }

                                Divider()
                                    .background(Color.gray.opacity(0.3))

                                HStack {
                                    Text("Current G-Force")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Spacer()
                                    Text(gForceMonitor.getGForceString())
                                        .font(.caption)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.white)
                                }

                                HStack {
                                    Text("Peak G-Force (Session)")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Spacer()
                                    Text(gForceMonitor.getPeakGForceString())
                                        .font(.caption)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.orange)
                                }

                                Button(action: { gForceMonitor.resetPeakGForce() }) {
                                    Text("Reset Peak")
                                        .font(.caption)
                                        .frame(maxWidth: .infinity)
                                        .padding(.vertical, 6)
                                        .background(Color.blue.opacity(0.2))
                                        .foregroundColor(.blue)
                                        .cornerRadius(6)
                                }
                            }

                            HStack(spacing: 8) {
                                Image(systemName: "info.circle.fill")
                                    .foregroundColor(.blue)
                                Text("Monitors acceleration during recording to detect impacts and aggressive driving")
                                    .font(.caption2)
                                    .foregroundColor(.blue)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.blue.opacity(0.1))
                            .cornerRadius(6)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Performance Metrics Status
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Performance Metrics", systemImage: "chart.line.uptrend.xyaxis")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                            }

                            VStack(spacing: 10) {
                                if performanceLogger.isRecording {
                                    HStack {
                                        Text("Recording FPS")
                                            .font(.caption)
                                            .foregroundColor(.gray)
                                        Spacer()
                                        Text(String(format: "%.1f fps", performanceLogger.recordingFPS))
                                            .font(.caption)
                                            .fontWeight(.semibold)
                                            .foregroundColor(.white)
                                    }

                                    HStack {
                                        Text("Memory Usage")
                                            .font(.caption)
                                            .foregroundColor(.gray)
                                        Spacer()
                                        Text(String(format: "%.0f MB", performanceLogger.memoryUsageMB))
                                            .font(.caption)
                                            .fontWeight(.semibold)
                                            .foregroundColor(.white)
                                    }

                                    HStack {
                                        Text("CPU Usage")
                                            .font(.caption)
                                            .foregroundColor(.gray)
                                        Spacer()
                                        Text(String(format: "%.1f%%", performanceLogger.cpuUsagePercent))
                                            .font(.caption)
                                            .fontWeight(.semibold)
                                            .foregroundColor(.white)
                                    }

                                    HStack {
                                        Text("Storage Write Speed")
                                            .font(.caption)
                                            .foregroundColor(.gray)
                                        Spacer()
                                        Text(String(format: "%.1f MB/s", performanceLogger.storageWriteSpeedMBps))
                                            .font(.caption)
                                            .fontWeight(.semibold)
                                            .foregroundColor(.white)
                                    }
                                } else {
                                    Text("Performance metrics displayed during recording")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                }
                            }

                            HStack(spacing: 8) {
                                Image(systemName: "info.circle.fill")
                                    .foregroundColor(.green)
                                Text("Monitors app performance including frame rate, memory, CPU, and storage write speed")
                                    .font(.caption2)
                                    .foregroundColor(.green)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.green.opacity(0.1))
                            .cornerRadius(6)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Permissions Status
                        PermissionStatusView()

                        // Audio & Watch Integration
                        AudioAndWatchView()

                        Divider()
                            .background(Color.gray.opacity(0.3))

                        // Parking Mode
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Parking Mode", systemImage: "parkingsign.circle.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                                Toggle("", isOn: Binding(
                                    get: { ParkingModeManager.shared.isParkingModeEnabled },
                                    set: { ParkingModeManager.shared.isParkingModeEnabled = $0 }
                                ))
                                .labelsHidden()
                            }

                            Text("Monitor vehicle when parked. Automatically records motion detection events and protects them.")
                                .font(.caption)
                                .foregroundColor(.gray)

                            HStack(spacing: 8) {
                                Image(systemName: "info.circle.fill")
                                    .foregroundColor(.blue)
                                    .font(.caption)
                                Text("Requires accelerometer - drains battery when recording")
                                    .font(.caption)
                                    .foregroundColor(.blue)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.blue.opacity(0.1))
                            .cornerRadius(6)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Auto-Start Recording
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Auto-Start Recording", systemImage: "play.circle.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                                Toggle("", isOn: Binding(
                                    get: { AutoStartRecordingManager.shared.isAutoStartEnabled },
                                    set: { AutoStartRecordingManager.shared.isAutoStartEnabled = $0 }
                                ))
                                .labelsHidden()
                            }

                            Text("Automatically start recording when driving is detected (>8 km/h for 5 seconds).")
                                .font(.caption)
                                .foregroundColor(.gray)

                            HStack(spacing: 8) {
                                Image(systemName: "info.circle.fill")
                                    .foregroundColor(.green)
                                    .font(.caption)
                                Text("Requires location access - uses GPS speed data")
                                    .font(.caption)
                                    .foregroundColor(.green)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.green.opacity(0.1))
                            .cornerRadius(6)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        Divider()
                            .background(Color.gray.opacity(0.3))

                        // Video Chunk Duration
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Video Chunk Duration", systemImage: "film.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                                Text("\(viewModel.chunkDurationMinutes) min")
                                    .font(.headline)
                                    .foregroundColor(.blue)
                            }

                            VStack(spacing: 8) {
                                Slider(
                                    value: Binding(
                                        get: { Double(viewModel.chunkDurationMinutes) },
                                        set: { viewModel.chunkDurationMinutes = Int($0) }
                                    ),
                                    in: 1...15,
                                    step: 1
                                )
                                .tint(.blue)

                                HStack(spacing: 20) {
                                    Text("1 min")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Spacer()
                                    Text("15 min")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                }
                            }

                            Text("Videos will automatically split into chunks. Smaller chunks use less storage per file.")
                                .font(.caption)
                                .foregroundColor(.gray)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Recording Frame Rate
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Recording Frame Rate", systemImage: "speedometer")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                                Text("\(viewModel.preferredRecordingFPS) fps")
                                    .font(.headline)
                                    .foregroundColor(.blue)
                            }

                            VStack(spacing: 10) {
                                ForEach([24, 30, 60], id: \.self) { fps in
                                    Button(action: { viewModel.preferredRecordingFPS = Int32(fps) }) {
                                        HStack(spacing: 12) {
                                            VStack(alignment: .leading, spacing: 4) {
                                                Text("\(fps) FPS")
                                                    .font(.subheadline)
                                                    .foregroundColor(.white)
                                                if fps == 24 {
                                                    Text("Film-like quality, smallest files")
                                                        .font(.caption)
                                                        .foregroundColor(.gray)
                                                } else if fps == 30 {
                                                    Text("Balanced quality & file size (default)")
                                                        .font(.caption)
                                                        .foregroundColor(.gray)
                                                } else {
                                                    Text("Smooth motion, largest files")
                                                        .font(.caption)
                                                        .foregroundColor(.gray)
                                                }
                                            }
                                            Spacer()
                                            if viewModel.preferredRecordingFPS == Int32(fps) {
                                                Image(systemName: "checkmark.circle.fill")
                                                    .foregroundColor(.blue)
                                            }
                                        }
                                        .padding(12)
                                        .background(viewModel.preferredRecordingFPS == Int32(fps) ? Color.blue.opacity(0.1) : Color.gray.opacity(0.05))
                                        .cornerRadius(8)
                                    }
                                    .foregroundColor(.primary)
                                }
                            }

                            VStack(spacing: 8) {
                                HStack(spacing: 8) {
                                    Image(systemName: "info.circle.fill")
                                        .foregroundColor(.blue)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Frame Rate Guide")
                                            .font(.caption2)
                                            .fontWeight(.semibold)
                                            .foregroundColor(.blue)
                                        Text("Higher FPS = smoother video but larger files. Affects thermal load during recording.")
                                            .font(.caption2)
                                            .foregroundColor(.blue)
                                    }
                                }
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.blue.opacity(0.1))
                            .cornerRadius(6)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Maximum Storage
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Maximum Storage", systemImage: "internaldrive.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                                Text(String(format: "%.0f GB", viewModel.maxStorageGB))
                                    .font(.headline)
                                    .foregroundColor(.blue)
                            }

                            VStack(spacing: 12) {
                                HStack(spacing: 12) {
                                    ForEach([5.0, 10.0, 20.0, 50.0], id: \.self) { gb in
                                        Button(action: { viewModel.maxStorageGB = gb }) {
                                            Text(String(format: "%.0f GB", gb))
                                                .font(.caption)
                                                .frame(maxWidth: .infinity)
                                                .padding(.vertical, 8)
                                                .background(viewModel.maxStorageGB == gb ? Color.blue : Color.gray.opacity(0.2))
                                                .foregroundColor(viewModel.maxStorageGB == gb ? .white : .gray)
                                                .cornerRadius(8)
                                        }
                                    }
                                }

                                VStack(spacing: 6) {
                                    HStack {
                                        Text("Custom:")
                                            .font(.caption)
                                            .foregroundColor(.gray)
                                        Spacer()
                                        Text(String(format: "%.1f GB", viewModel.maxStorageGB))
                                            .font(.caption)
                                            .foregroundColor(.white)
                                    }
                                    Slider(
                                        value: $viewModel.maxStorageGB,
                                        in: 1...100,
                                        step: 0.5
                                    )
                                    .tint(.blue)
                                }
                            }

                            Text("Old unprotected videos are automatically deleted when storage limit is reached.")
                                .font(.caption)
                                .foregroundColor(.gray)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Reserved System Space
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Reserved System Space", systemImage: "lock.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                                Text(String(format: "%.1f GB", viewModel.reservedSystemSpaceGB))
                                    .font(.headline)
                                    .foregroundColor(.blue)
                            }

                            VStack(spacing: 12) {
                                HStack(spacing: 12) {
                                    ForEach([1.0, 3.0, 5.0, 10.0], id: \.self) { gb in
                                        Button(action: { viewModel.reservedSystemSpaceGB = gb }) {
                                            Text(String(format: "%.0f GB", gb))
                                                .font(.caption)
                                                .frame(maxWidth: .infinity)
                                                .padding(.vertical, 8)
                                                .background(viewModel.reservedSystemSpaceGB == gb ? Color.blue : Color.gray.opacity(0.2))
                                                .foregroundColor(viewModel.reservedSystemSpaceGB == gb ? .white : .gray)
                                                .cornerRadius(8)
                                        }
                                    }
                                }

                                VStack(spacing: 6) {
                                    HStack {
                                        Text("Custom:")
                                            .font(.caption)
                                            .foregroundColor(.gray)
                                        Spacer()
                                        Text(String(format: "%.1f GB", viewModel.reservedSystemSpaceGB))
                                            .font(.caption)
                                            .foregroundColor(.white)
                                    }
                                    Slider(
                                        value: $viewModel.reservedSystemSpaceGB,
                                        in: 1...50,
                                        step: 0.5
                                    )
                                    .tint(.blue)
                                }
                            }

                            Text("Prevents the app from using all device storage, ensuring the system remains responsive. The app will not store more than (Device Storage - Reserved Space).")
                                .font(.caption)
                                .foregroundColor(.gray)

                            HStack(spacing: 8) {
                                Image(systemName: "info.circle.fill")
                                    .foregroundColor(.blue)
                                Text("Device Storage: \(String(format: "%.1f GB", storageManager.getDeviceTotalStorage()))")
                                    .font(.caption2)
                                    .foregroundColor(.blue)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.blue.opacity(0.1))
                            .cornerRadius(6)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Current Storage Info
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Current Storage Usage", systemImage: "chart.pie.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                            }

                            VStack(spacing: 12) {
                                let effectiveMax = storageManager.getEffectiveMaxStorage(userMax: viewModel.maxStorageGB, reservedGB: viewModel.reservedSystemSpaceGB)
                                ProgressView(value: min(viewModel.currentStorageGB / effectiveMax, 1.0))
                                    .tint(.blue)

                                HStack {
                                    Text(String(format: "%.2f GB used", viewModel.currentStorageGB))
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Spacer()
                                    Text(String(format: "%.2f GB available", max(0, effectiveMax - viewModel.currentStorageGB)))
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                }
                            }
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Video Quality Selection
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Video Quality", systemImage: "sparkles")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                                Text(qualityManager.selectedQualityMode.displayName)
                                    .font(.headline)
                                    .foregroundColor(.blue)
                            }

                            VStack(spacing: 10) {
                                ForEach(VideoQualityMode.allCases, id: \.self) { mode in
                                    Button(action: {
                                        qualityManager.selectedQualityMode = mode
                                    }) {
                                        HStack(spacing: 12) {
                                            VStack(alignment: .leading, spacing: 4) {
                                                Text(mode.displayName)
                                                    .font(.subheadline)
                                                    .foregroundColor(.white)
                                                Text(mode.description)
                                                    .font(.caption)
                                                    .foregroundColor(.gray)
                                            }
                                            Spacer()
                                            if qualityManager.selectedQualityMode == mode {
                                                Image(systemName: "checkmark.circle.fill")
                                                    .foregroundColor(.blue)
                                            }
                                        }
                                        .padding(12)
                                        .background(qualityManager.selectedQualityMode == mode ? Color.blue.opacity(0.1) : Color.gray.opacity(0.05))
                                        .cornerRadius(8)
                                    }
                                    .foregroundColor(.primary)
                                }
                            }

                            VStack(alignment: .leading, spacing: 8) {
                                HStack(spacing: 8) {
                                    Image(systemName: "info.circle.fill")
                                        .foregroundColor(.blue)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Storage impact: \(String(format: "%.0f%%", qualityManager.storageMultiplier * 100))")
                                            .font(.caption)
                                            .foregroundColor(.blue)
                                        Text(qualityManager.qualityDescription)
                                            .font(.caption2)
                                            .foregroundColor(.blue)
                                    }
                                }
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.blue.opacity(0.1))
                            .cornerRadius(6)

                            Toggle("Low Light Boost", isOn: $qualityManager.lowLightBoostEnabled)
                                .font(.caption)
                                .foregroundColor(.white)
                                .padding(.horizontal, 4)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Video Codec Selection
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Video Codec", systemImage: "video.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                                Text(selectedCodec.rawValue)
                                    .font(.headline)
                                    .foregroundColor(.blue)
                            }

                            VStack(spacing: 10) {
                                ForEach(VideoCodec.allCases, id: \.self) { codec in
                                    Button(action: {
                                        selectedCodec = codec
                                        VideoCodecManager.shared.selectedCodec = codec
                                    }) {
                                        HStack(spacing: 12) {
                                            VStack(alignment: .leading, spacing: 4) {
                                                Text(codec.displayName)
                                                    .font(.subheadline)
                                                    .foregroundColor(.white)
                                                Text(codec.description)
                                                    .font(.caption)
                                                    .foregroundColor(.gray)
                                                Text(codec.storageEstimate)
                                                    .font(.caption2)
                                                    .foregroundColor(.gray)
                                                    .italic()
                                            }
                                            Spacer()
                                            if selectedCodec == codec {
                                                Image(systemName: "checkmark.circle.fill")
                                                    .foregroundColor(.blue)
                                            }
                                        }
                                        .padding(12)
                                        .background(selectedCodec == codec ? Color.blue.opacity(0.1) : Color.gray.opacity(0.05))
                                        .cornerRadius(8)
                                    }
                                    .foregroundColor(.primary)
                                }
                            }

                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 8) {
                                    Image(systemName: "info.circle.fill")
                                        .foregroundColor(.blue)
                                    Text("HEVC saves ~40% storage vs H.264")
                                        .font(.caption)
                                        .foregroundColor(.blue)
                                }
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.blue.opacity(0.1))
                            .cornerRadius(6)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Night Mode
                        if nightModeManager.isSupported {
                            VStack(alignment: .leading, spacing: 12) {
                                HStack {
                                    Label("Night Mode", systemImage: "moon.stars.fill")
                                        .font(.headline)
                                        .foregroundColor(.white)
                                    Spacer()
                                    Toggle("", isOn: $nightModeManager.isEnabled)
                                        .labelsHidden()
                                }

                                // Manual/Automatic Mode Selection
                                VStack(spacing: 10) {
                                    HStack(spacing: 12) {
                                        Button(action: { nightModeManager.isAutomatic = false }) {
                                            HStack(spacing: 8) {
                                                Image(systemName: nightModeManager.isAutomatic ? "circle" : "circle.fill")
                                                Text("Manual")
                                                    .font(.caption)
                                                    .fontWeight(.semibold)
                                            }
                                            .frame(maxWidth: .infinity)
                                            .padding(.vertical, 8)
                                            .background(!nightModeManager.isAutomatic ? Color.blue.opacity(0.2) : Color.gray.opacity(0.1))
                                            .foregroundColor(!nightModeManager.isAutomatic ? .blue : .gray)
                                            .cornerRadius(8)
                                        }

                                        Button(action: { nightModeManager.isAutomatic = true }) {
                                            HStack(spacing: 8) {
                                                Image(systemName: nightModeManager.isAutomatic ? "circle.fill" : "circle")
                                                Text("Automatic")
                                                    .font(.caption)
                                                    .fontWeight(.semibold)
                                            }
                                            .frame(maxWidth: .infinity)
                                            .padding(.vertical, 8)
                                            .background(nightModeManager.isAutomatic ? Color.blue.opacity(0.2) : Color.gray.opacity(0.1))
                                            .foregroundColor(nightModeManager.isAutomatic ? .blue : .gray)
                                            .cornerRadius(8)
                                        }
                                    }
                                }

                                Text(nightModeManager.getNightModeDescription())
                                    .font(.caption)
                                    .foregroundColor(.gray)

                                // Automatic Mode Threshold Control
                                if nightModeManager.isAutomatic {
                                    VStack(spacing: 10) {
                                        HStack {
                                            Text("Brightness Threshold")
                                                .font(.caption)
                                                .foregroundColor(.gray)
                                            Spacer()
                                            Text(String(format: "%.1f EV", nightModeManager.brightnessThreshold))
                                                .font(.caption)
                                                .fontWeight(.semibold)
                                                .foregroundColor(.white)
                                        }

                                        Slider(
                                            value: $nightModeManager.brightnessThreshold,
                                            in: -8.0...(-2.0),
                                            step: 0.5
                                        )
                                        .tint(.blue)

                                        HStack(spacing: 20) {
                                            Text("Very Dark")
                                                .font(.caption2)
                                                .foregroundColor(.gray)
                                            Spacer()
                                            Text("Bright")
                                                .font(.caption2)
                                                .foregroundColor(.gray)
                                        }

                                        HStack {
                                            Text("Current Brightness")
                                                .font(.caption)
                                                .foregroundColor(.gray)
                                            Spacer()
                                            Text(String(format: "%.1f EV", nightModeManager.currentBrightness))
                                                .font(.caption)
                                                .fontWeight(.semibold)
                                                .foregroundColor(nightModeManager.currentBrightness < nightModeManager.brightnessThreshold ? .red : .green)
                                        }
                                    }
                                    .padding(10)
                                    .background(Color.orange.opacity(0.05))
                                    .cornerRadius(6)
                                }

                                // Extended Exposure Settings
                                VStack(spacing: 10) {
                                    HStack {
                                        Text("Extended Exposure")
                                            .font(.caption)
                                            .foregroundColor(.gray)
                                        Spacer()
                                        Toggle("", isOn: $nightModeManager.useExtendedExposure)
                                            .labelsHidden()
                                    }

                                    if nightModeManager.useExtendedExposure {
                                        VStack(spacing: 8) {
                                            HStack {
                                                Text("Exposure Time")
                                                    .font(.caption)
                                                    .foregroundColor(.gray)
                                                Spacer()
                                                Text(String(format: "%.2f ms", nightModeManager.exposureDurationMs))
                                                    .font(.caption)
                                                    .fontWeight(.semibold)
                                                    .foregroundColor(.white)
                                            }

                                            Slider(
                                                value: $nightModeManager.exposureDurationMs,
                                                in: 8.33...33.33,
                                                step: 0.5
                                            )
                                            .tint(.green)

                                            HStack(spacing: 20) {
                                                VStack(alignment: .leading, spacing: 2) {
                                                    Text("8.33ms")
                                                        .font(.caption2)
                                                        .foregroundColor(.gray)
                                                    Text("1/120s")
                                                        .font(.caption2)
                                                        .foregroundColor(.gray)
                                                }
                                                Spacer()
                                                VStack(alignment: .trailing, spacing: 2) {
                                                    Text("33.33ms")
                                                        .font(.caption2)
                                                        .foregroundColor(.gray)
                                                    Text("1/30s")
                                                        .font(.caption2)
                                                        .foregroundColor(.gray)
                                                }
                                            }

                                            HStack(spacing: 8) {
                                                Image(systemName: "exclamationmark.circle.fill")
                                                    .foregroundColor(.orange)
                                                    .font(.caption)
                                                Text("Longer exposure captures more light but may cause motion blur at driving speeds")
                                                    .font(.caption2)
                                                    .foregroundColor(.orange)
                                            }
                                            .padding(8)
                                            .background(Color.orange.opacity(0.1))
                                            .cornerRadius(4)
                                        }
                                    }
                                }
                                .padding(10)
                                .background(Color.green.opacity(0.05))
                                .cornerRadius(6)

                                VStack(spacing: 6) {
                                    HStack(spacing: 8) {
                                        Image(systemName: "info.circle.fill")
                                            .foregroundColor(.blue)
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text("Low Light Enhancement")
                                                .font(.caption2)
                                                .fontWeight(.semibold)
                                                .foregroundColor(.blue)
                                            if nightModeManager.isAutomatic {
                                                Text("Automatically boosts brightness when scene gets darker than threshold")
                                                    .font(.caption2)
                                                    .foregroundColor(.blue)
                                            } else {
                                                Text("Boosts video brightness and reduces noise in dark conditions")
                                                    .font(.caption2)
                                                    .foregroundColor(.blue)
                                            }
                                        }
                                    }
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Color.blue.opacity(0.1))
                                .cornerRadius(6)
                            }
                            .padding(16)
                            .background(Color.gray.opacity(0.1))
                            .cornerRadius(12)
                        }

                        Spacer()
                    }
                    .padding(20)

                    // Storage Location
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Label("Storage Location", systemImage: "externaldrive.fill")
                                .font(.headline)
                                .foregroundColor(.white)
                            Spacer()
                        }

                        VStack(spacing: 10) {
                            ForEach(StorageLocation.allCases, id: \.self) { location in
                                Button(action: {
                                    let oldLocation = selectedStorageLocation
                                    selectedStorageLocation = location
                                    StorageLocationManager.shared.selectedLocation = location

                                    if oldLocation != location && location == .onDevice {
                                        migrationMessage = "⚠️ Files stored on device will be deleted if the app is uninstalled!"
                                        showMigrationAlert = true
                                    } else if oldLocation != location && location == .iCloud {
                                        migrationMessage = "Your existing recordings will be migrated to iCloud Drive.\n\nMake sure iCloud is enabled in Settings > [Your Name] > iCloud."
                                        showMigrationAlert = true
                                        StorageLocationManager.shared.migrateRecordings(from: oldLocation)
                                    } else if oldLocation != location && location == .iCloudWiFiOnly {
                                        migrationMessage = "Your existing recordings will be migrated to iCloud Drive (Wi-Fi only).\n\nFiles will only upload when connected to Wi-Fi to save cellular data. Make sure iCloud is enabled in Settings > [Your Name] > iCloud."
                                        showMigrationAlert = true
                                        StorageLocationManager.shared.migrateRecordings(from: oldLocation)
                                    } else if oldLocation != location && location == .iCloudLocal {
                                        migrationMessage = "Your existing recordings will be migrated to the iCloud folder (local only).\n\nFiles persist even if app is uninstalled, with no cloud upload or cellular data usage."
                                        showMigrationAlert = true
                                        StorageLocationManager.shared.migrateRecordings(from: oldLocation)
                                    } else if oldLocation != location && location == .iCloudLocalBackup {
                                        migrationMessage = "Your existing recordings will be migrated to the protected iCloud folder.\n\nFiles are protected locally AND automatically backed up to iCloud Drive for redundancy."
                                        showMigrationAlert = true
                                        StorageLocationManager.shared.migrateRecordings(from: oldLocation)
                                    } else if oldLocation != location && location == .filesApp {
                                        migrationMessage = "Your existing recordings will be migrated to the Files app folder.\n\nAccess them in the Files app > On My iPhone > Dashcam > Dashcam Recordings."
                                        showMigrationAlert = true
                                        StorageLocationManager.shared.migrateRecordings(from: oldLocation)
                                    }
                                }) {
                                    HStack(spacing: 12) {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(location.displayName)
                                                .font(.subheadline)
                                                .foregroundColor(.white)
                                            Text(location.description)
                                                .font(.caption)
                                                .foregroundColor(.gray)
                                        }
                                        Spacer()
                                        if selectedStorageLocation == location {
                                            Image(systemName: "checkmark.circle.fill")
                                                .foregroundColor(.blue)
                                        }
                                    }
                                    .padding(12)
                                    .background(selectedStorageLocation == location ? Color.blue.opacity(0.1) : Color.gray.opacity(0.05))
                                    .cornerRadius(8)
                                }
                                .foregroundColor(.primary)
                            }

                            if selectedStorageLocation == .onDevice {
                                VStack(spacing: 8) {
                                    HStack(spacing: 8) {
                                        Image(systemName: "exclamationmark.triangle.fill")
                                            .foregroundColor(.red)
                                        Text("Files deleted when app is uninstalled")
                                            .font(.caption)
                                            .foregroundColor(.red)
                                    }
                                    Text("Recordings are stored only on your device storage. They will be permanently deleted if you uninstall the app.")
                                        .font(.caption2)
                                        .foregroundColor(.gray)
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Color.red.opacity(0.1))
                                .cornerRadius(6)
                            } else if selectedStorageLocation == .iCloud {
                                VStack(spacing: 8) {
                                    HStack(spacing: 8) {
                                        Image(systemName: "icloud.fill")
                                            .foregroundColor(.blue)
                                        Text("High upload traffic over cellular")
                                            .font(.caption)
                                            .foregroundColor(.blue)
                                    }
                                    Text("iCloud automatically uploads files over your mobile network. Large video files will consume significant data. Consider using Wi-Fi for best results.")
                                        .font(.caption2)
                                        .foregroundColor(.gray)
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Color.blue.opacity(0.1))
                                .cornerRadius(6)
                            } else if selectedStorageLocation == .iCloudWiFiOnly {
                                VStack(spacing: 8) {
                                    HStack(spacing: 8) {
                                        Image(systemName: "wifi")
                                            .foregroundColor(.green)
                                        Text("Wi-Fi uploads only - saves cellular data")
                                            .font(.caption)
                                            .foregroundColor(.green)
                                    }
                                    Text("iCloud sync only happens over Wi-Fi. Recordings remain local until Wi-Fi is available, then automatically upload to iCloud.")
                                        .font(.caption2)
                                        .foregroundColor(.gray)
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Color.green.opacity(0.1))
                                .cornerRadius(6)
                            } else if selectedStorageLocation == .iCloudLocal {
                                VStack(spacing: 8) {
                                    HStack(spacing: 8) {
                                        Image(systemName: "checkmark.circle.fill")
                                            .foregroundColor(.green)
                                        Text("No cloud upload or cellular data")
                                            .font(.caption)
                                            .foregroundColor(.green)
                                    }
                                    Text("Files are stored in the iCloud folder but remain local. They persist even if you uninstall the app, with zero cellular data usage.")
                                        .font(.caption2)
                                        .foregroundColor(.gray)
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Color.green.opacity(0.1))
                                .cornerRadius(6)
                            } else if selectedStorageLocation == .iCloudLocalBackup {
                                VStack(spacing: 8) {
                                    HStack(spacing: 8) {
                                        Image(systemName: "checkmark.circle.fill")
                                            .foregroundColor(.green)
                                        Text("Local + Cloud backup protection")
                                            .font(.caption)
                                            .foregroundColor(.green)
                                    }
                                    Text("Files are protected locally in iCloud folder and automatically backed up to iCloud Drive. Best protection with redundancy on two locations.")
                                        .font(.caption2)
                                        .foregroundColor(.gray)
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Color.green.opacity(0.1))
                                .cornerRadius(6)
                            } else {
                                HStack(spacing: 8) {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundColor(.green)
                                    Text("Files persist even if app is uninstalled")
                                        .font(.caption)
                                        .foregroundColor(.green)
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Color.green.opacity(0.1))
                                .cornerRadius(6)
                            }
                        }

                        if selectedStorageLocation == .iCloud {
                            Text("Enable iCloud in Settings > [Your Name] > iCloud > Dashcam App")
                                .font(.caption2)
                                .foregroundColor(.orange)
                                .padding(.top, 4)
                        } else if selectedStorageLocation == .iCloudWiFiOnly {
                            Text("Enable iCloud in Settings > [Your Name] > iCloud > Dashcam App. Syncing restricted to Wi-Fi only.")
                                .font(.caption2)
                                .foregroundColor(.blue)
                                .padding(.top, 4)
                        } else if selectedStorageLocation == .iCloudLocal {
                            Text("Files stored locally in iCloud folder - accessible via Xcode or recovered after reinstall")
                                .font(.caption2)
                                .foregroundColor(.blue)
                                .padding(.top, 4)
                        } else if selectedStorageLocation == .iCloudLocalBackup {
                            Text("Files protected locally AND backed up to iCloud. Enable iCloud in Settings > [Your Name] > iCloud > Dashcam App")
                                .font(.caption2)
                                .foregroundColor(.blue)
                                .padding(.top, 4)
                        } else if selectedStorageLocation == .filesApp {
                            Text("Access your recordings in Files app > On My iPhone > Dashcam Recordings")
                                .font(.caption2)
                                .foregroundColor(.blue)
                                .padding(.top, 4)
                        }
                    }
                    .padding(16)
                    .background(Color.gray.opacity(0.1))
                    .cornerRadius(12)
                }
                .padding(20)
            }
        }
        .alert("Storage Location Changed", isPresented: $showMigrationAlert) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(migrationMessage)
        }
    }
}

extension View {
    func borderBottom(_ color: Color) -> some View {
        VStack {
            self
            Divider()
                .background(color)
        }
    }
}

#Preview {
    SettingsView()
        .environmentObject(CameraDashcamViewModel())
}
