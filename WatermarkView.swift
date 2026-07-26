import SwiftUI

struct WatermarkView: View {
    @ObservedObject var fpsCounter: FPSCounter
    @ObservedObject var batteryManager: BatteryMonitorManager
    let timestamp: Date

    var formattedTime: String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: timestamp)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // Top left: FPS and recording info
            HStack(spacing: 8) {
                HStack(spacing: 4) {
                    Image(systemName: "hare.fill")
                        .font(.caption)
                    Text("\(fpsCounter.currentFPS) fps")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .monospacedDigit()
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color.black.opacity(0.6))
                .cornerRadius(4)

                HStack(spacing: 4) {
                    Image(systemName: "clock.fill")
                        .font(.caption)
                    Text(formattedTime)
                        .font(.caption)
                        .fontWeight(.semibold)
                        .monospacedDigit()
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color.black.opacity(0.6))
                .cornerRadius(4)

                Spacer()

                HStack(spacing: 4) {
                    Image(systemName: batteryManager.batteryLevel > 0.2 ? "battery.50" : "battery.25")
                        .font(.caption)
                        .foregroundColor(batteryManager.batteryLevel > 0.2 ? .green : .orange)
                    Text(batteryManager.batteryPercentage)
                        .font(.caption)
                        .fontWeight(.semibold)
                        .monospacedDigit()
                        .foregroundColor(batteryManager.batteryLevel > 0.2 ? .green : .orange)
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color.black.opacity(0.6))
                .cornerRadius(4)
            }

            Spacer()
        }
        .padding(12)
        .font(.caption)
        .foregroundColor(.white)
    }
}

#Preview {
    ZStack {
        Color.black
            .ignoresSafeArea()

        VStack {
            WatermarkView(
                fpsCounter: FPSCounter(),
                batteryManager: BatteryMonitorManager.shared,
                timestamp: Date()
            )
            Spacer()
        }
    }
}
