import SwiftUI

struct BatteryStatusView: View {
    @StateObject private var batteryManager = BatteryMonitorManager.shared

    var body: some View {
        VStack(spacing: 8) {
            HStack(spacing: 12) {
                Image(systemName: getBatteryIcon())
                    .foregroundColor(getBatteryColor())
                    .font(.system(size: 20))

                VStack(alignment: .leading, spacing: 2) {
                    Text("Battery")
                        .font(.caption)
                        .foregroundColor(.gray)
                    Text(batteryManager.batteryPercentage)
                        .font(.subheadline)
                        .fontWeight(.semibold)
                        .foregroundColor(.white)
                }

                Spacer()

                VStack(alignment: .trailing, spacing: 2) {
                    Text(batteryManager.batteryStatusDescription)
                        .font(.caption)
                        .foregroundColor(getBatteryColor())

                    if batteryManager.isCharging {
                        HStack(spacing: 2) {
                            Image(systemName: "bolt.fill")
                                .font(.caption2)
                            Text("Charging")
                                .font(.caption2)
                        }
                        .foregroundColor(.green)
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color.gray.opacity(0.1))
            .cornerRadius(8)

            if batteryManager.shouldShowLowBatteryWarning {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Low Battery")
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundColor(.orange)
                        Text("Consider charging to continue recording")
                            .font(.caption2)
                            .foregroundColor(.orange)
                    }
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.orange.opacity(0.1))
                .cornerRadius(8)
            }

            if batteryManager.shouldStopRecording {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.circle.fill")
                        .foregroundColor(.red)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Critical Battery")
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundColor(.red)
                        Text("Battery below 10%. Please charge immediately.")
                            .font(.caption2)
                            .foregroundColor(.red)
                    }
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.red.opacity(0.1))
                .cornerRadius(8)
            }

            if batteryManager.showLowBatteryAlert {
                HStack(spacing: 8) {
                    Image(systemName: "speaker.wave.2.fill")
                        .foregroundColor(.yellow)
                        .animation(.easeInOut(duration: 0.5).repeatForever(autoreverses: true), value: batteryManager.showLowBatteryAlert)
                    Text("Low battery beep alert playing")
                        .font(.caption)
                        .foregroundColor(.yellow)
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.yellow.opacity(0.1))
                .cornerRadius(8)
            }
        }
    }

    private func getBatteryIcon() -> String {
        if batteryManager.isCharging {
            return "battery.100.bolt"
        }

        let level = batteryManager.batteryLevel
        if level > 0.75 {
            return "battery.100"
        } else if level > 0.5 {
            return "battery.75"
        } else if level > 0.25 {
            return "battery.50"
        } else {
            return "battery.25"
        }
    }

    private func getBatteryColor() -> Color {
        if batteryManager.isCharging {
            return .green
        }

        let level = batteryManager.batteryLevel
        let criticalBatteryThreshold: Double = 0.1  // 10% - hardcoded value
        if level < criticalBatteryThreshold {
            return .red
        } else if level < 0.20 {
            return .orange
        } else if level < 0.5 {
            return .yellow
        } else {
            return .green
        }
    }
}

#Preview {
    BatteryStatusView()
}
