import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel
    @Environment(\.dismiss) var dismiss
    @StateObject private var qualityManager = VideoQualityManager.shared
    @StateObject private var gForceMonitor = GForceMonitor.shared
    @StateObject private var performanceLogger = PerformanceLogger.shared
    @State private var selectedStorageLocation = StorageLocationManager.shared.selectedLocation
    @State private var selectedCodec = VideoCodecManager.shared.selectedCodec
    @State private var showMigrationAlert = false
    @State private var migrationMessage = ""

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
                                    value: Double(viewModel.chunkDurationMinutes),
                                    in: 1...15,
                                    step: 1
                                ) { _ in } onEditingChanged: { _ in
                                    // Update happens via didSet
                                }
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

                        // Current Storage Info
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Current Storage Usage", systemImage: "chart.pie.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                            }

                            VStack(spacing: 12) {
                                ProgressView(value: min(viewModel.currentStorageGB / viewModel.maxStorageGB, 1.0))
                                    .tint(.blue)

                                HStack {
                                    Text(String(format: "%.2f GB used", viewModel.currentStorageGB))
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Spacer()
                                    Text(String(format: "%.2f GB available", max(0, viewModel.maxStorageGB - viewModel.currentStorageGB)))
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
                                    } else if oldLocation != location && location == .photos {
                                        migrationMessage = "Videos will be saved to your Photos library and backed up locally.\n\nMake sure Photos permission is enabled."
                                        showMigrationAlert = true
                                        StorageLocationManager.shared.requestPhotosPermission { _ in }
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
                                HStack(spacing: 8) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundColor(.red)
                                    Text("Files will be deleted when app is uninstalled!")
                                        .font(.caption)
                                        .foregroundColor(.red)
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Color.red.opacity(0.1))
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

                        Text(StorageLocation.iCloud.rawValue == selectedStorageLocation.rawValue ? "Enable iCloud in Settings > [Your Name] > iCloud > Dashcam App" : "")
                            .font(.caption2)
                            .foregroundColor(.orange)
                            .padding(.top, 4)
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
