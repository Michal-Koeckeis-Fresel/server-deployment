import SwiftUI

struct PerformanceDashboardView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel
    @StateObject private var gForceMonitor = GForceMonitor.shared
    @StateObject private var performanceLogger = PerformanceLogger.shared
    @Environment(\.dismiss) var dismiss

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
                    Text("Performance Dashboard")
                        .font(.headline)
                        .foregroundColor(.white)
                    Spacer()
                    Color.clear.frame(width: 44)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 16)
                .borderBottom(Color.gray.opacity(0.2))

                ScrollView {
                    VStack(spacing: 20) {
                        // Recording Status Card
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Circle()
                                    .fill(viewModel.isRecording ? Color.red : Color.gray)
                                    .frame(width: 12, height: 12)
                                Text(viewModel.isRecording ? "Recording Active" : "Not Recording")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                                Text(viewModel.recordingTime)
                                    .font(.subheadline)
                                    .fontWeight(.semibold)
                                    .foregroundColor(.red)
                            }
                        }
                        .padding(16)
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(12)

                        // G-Force Analytics
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Image(systemName: "waveform.circle.fill")
                                    .foregroundColor(.orange)
                                Text("G-Force Analytics")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                            }

                            VStack(spacing: 12) {
                                // Current G-Force
                                AnalyticsRow(
                                    label: "Current G-Force",
                                    value: gForceMonitor.getGForceString(),
                                    color: .white
                                )

                                // Peak G-Force
                                AnalyticsRow(
                                    label: "Peak G-Force",
                                    value: gForceMonitor.getPeakGForceString(),
                                    color: .orange
                                )

                                // Average G-Force
                                AnalyticsRow(
                                    label: "Average G-Force",
                                    value: gForceMonitor.getAverageGForceString(),
                                    color: .white
                                )

                                // Acceleration Components
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("Acceleration Components")
                                        .font(.caption)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.gray)

                                    let (x, y, z) = gForceMonitor.accelerometerData
                                    HStack(spacing: 12) {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text("X (Lateral)")
                                                .font(.caption2)
                                                .foregroundColor(.gray)
                                            Text(String(format: "%.2f m/s²", x))
                                                .font(.caption)
                                                .fontWeight(.semibold)
                                                .foregroundColor(.blue)
                                        }

                                        Divider()

                                        VStack(alignment: .leading, spacing: 4) {
                                            Text("Y (Fwd/Back)")
                                                .font(.caption2)
                                                .foregroundColor(.gray)
                                            Text(String(format: "%.2f m/s²", y))
                                                .font(.caption)
                                                .fontWeight(.semibold)
                                                .foregroundColor(.green)
                                        }

                                        Divider()

                                        VStack(alignment: .leading, spacing: 4) {
                                            Text("Z (Vertical)")
                                                .font(.caption2)
                                                .foregroundColor(.gray)
                                            Text(String(format: "%.2f m/s²", z))
                                                .font(.caption)
                                                .fontWeight(.semibold)
                                                .foregroundColor(.purple)
                                        }
                                    }
                                    .padding(10)
                                    .background(Color.gray.opacity(0.05))
                                    .cornerRadius(6)
                                }
                            }
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Performance Metrics
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Image(systemName: "chart.line.uptrend.xyaxis")
                                    .foregroundColor(.green)
                                Text("Performance Metrics")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                            }

                            VStack(spacing: 12) {
                                // FPS Gauge
                                PerformanceGauge(
                                    label: "Frame Rate",
                                    value: performanceLogger.recordingFPS,
                                    unit: "fps",
                                    max: 60,
                                    color: .blue
                                )

                                // Memory Usage
                                PerformanceGauge(
                                    label: "Memory Usage",
                                    value: performanceLogger.memoryUsageMB,
                                    unit: "MB",
                                    max: 800,
                                    color: .cyan
                                )

                                // CPU Usage
                                PerformanceGauge(
                                    label: "CPU Usage",
                                    value: performanceLogger.cpuUsagePercent,
                                    unit: "%",
                                    max: 100,
                                    color: .yellow
                                )

                                // Storage Write Speed
                                AnalyticsRow(
                                    label: "Storage Write Speed",
                                    value: String(format: "%.1f MB/s", performanceLogger.storageWriteSpeedMBps),
                                    color: .white
                                )
                            }
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // System Health
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Image(systemName: "heart.circle.fill")
                                    .foregroundColor(.red)
                                Text("System Health")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                            }

                            VStack(spacing: 8) {
                                HealthIndicator(
                                    label: "Thermal Status",
                                    status: SystemPressureMonitor.shared.shouldPauseRecording ? "Critical" :
                                           SystemPressureMonitor.shared.shouldReduceQuality ? "Elevated" : "Normal",
                                    color: SystemPressureMonitor.shared.shouldPauseRecording ? .red :
                                          SystemPressureMonitor.shared.shouldReduceQuality ? .orange : .green
                                )

                                HealthIndicator(
                                    label: "Battery Level",
                                    status: BatteryMonitorManager.shared.batteryPercentage,
                                    color: BatteryMonitorManager.shared.batteryLevel > 0.2 ? .green : .orange
                                )

                                HealthIndicator(
                                    label: "Low Power Mode",
                                    status: LowPowerModeMonitor.shared.isLowPowerModeEnabled ? "Active" : "Off",
                                    color: LowPowerModeMonitor.shared.isLowPowerModeEnabled ? .orange : .gray
                                )

                                HealthIndicator(
                                    label: "Storage Health",
                                    status: String(format: "%.1f%%", (viewModel.currentStorageGB / viewModel.maxStorageGB) * 100),
                                    color: (viewModel.currentStorageGB / viewModel.maxStorageGB) > 0.9 ? .red :
                                          (viewModel.currentStorageGB / viewModel.maxStorageGB) > 0.7 ? .orange : .green
                                )
                            }
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Recording Information
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Image(systemName: "info.circle.fill")
                                    .foregroundColor(.blue)
                                Text("Recording Information")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                            }

                            VStack(spacing: 10) {
                                InfoRow(
                                    label: "Storage Used",
                                    value: String(format: "%.2f GB", viewModel.currentStorageGB)
                                )

                                InfoRow(
                                    label: "Current Chunk",
                                    value: "Chunk #\(viewModel.currentChunkNumber)"
                                )

                                InfoRow(
                                    label: "Chunk Duration",
                                    value: "\(viewModel.chunkDurationMinutes) min"
                                )

                                InfoRow(
                                    label: "Active Cameras",
                                    value: "\(viewModel.cameraStatus.count) cameras"
                                )
                            }
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)
                    }
                    .padding(16)
                }
            }
        }
        .navigationBarHidden(true)
    }
}

struct AnalyticsRow: View {
    let label: String
    let value: String
    let color: Color

    var body: some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundColor(.gray)
            Spacer()
            Text(value)
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(color)
        }
        .padding(10)
        .background(Color.gray.opacity(0.05))
        .cornerRadius(6)
    }
}

struct PerformanceGauge: View {
    let label: String
    let value: Double
    let unit: String
    let max: Double
    let color: Color

    var percentage: Double {
        Swift.min(Swift.max(value / max, 0), 1)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(label)
                    .font(.caption)
                    .foregroundColor(.gray)
                Spacer()
                Text(String(format: "%.1f %@", value, unit))
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(.white)
            }

            ProgressView(value: percentage)
                .tint(color)
                .frame(height: 6)
        }
        .padding(10)
        .background(Color.gray.opacity(0.05))
        .cornerRadius(6)
    }
}

struct HealthIndicator: View {
    let label: String
    let status: String
    let color: Color

    var body: some View {
        HStack {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)

            Text(label)
                .font(.caption)
                .foregroundColor(.gray)

            Spacer()

            Text(status)
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(color)
        }
        .padding(10)
        .background(Color.gray.opacity(0.05))
        .cornerRadius(6)
    }
}

struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundColor(.gray)
            Spacer()
            Text(value)
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(.white)
        }
    }
}

#Preview {
    PerformanceDashboardView()
        .environmentObject(CameraDashcamViewModel())
}
