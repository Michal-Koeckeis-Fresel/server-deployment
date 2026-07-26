import SwiftUI

struct SystemPressureView: View {
    @StateObject private var pressureMonitor = SystemPressureMonitor.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("System Pressure", systemImage: "thermometer.sun.fill")
                    .font(.headline)
                    .foregroundColor(.white)
                Spacer()
                HStack(spacing: 4) {
                    Image(systemName: pressureMonitor.pressureLevel.icon)
                        .foregroundColor(pressureMonitor.pressureLevel.color)
                    Text(pressureMonitor.pressureLevel.rawValue)
                        .font(.headline)
                        .foregroundColor(pressureMonitor.pressureLevel.color)
                }
            }

            VStack(spacing: 8) {
                HStack {
                    Text("Thermal State")
                        .font(.caption)
                        .foregroundColor(.gray)
                    Spacer()
                    Text(pressureMonitor.thermalStateDescription)
                        .font(.caption)
                        .foregroundColor(.white)
                }

                HStack {
                    Text("Pressure Level")
                        .font(.caption)
                        .foregroundColor(.gray)
                    Spacer()
                    Text(String(format: "%.0f%%", pressureMonitor.thermalPressure * 100))
                        .font(.caption)
                        .foregroundColor(.white)
                }

                ProgressView(value: Double(pressureMonitor.thermalPressure))
                    .tint(pressureMonitor.pressureLevel.color)
            }

            VStack(spacing: 6) {
                if pressureMonitor.shouldReduceQuality {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.orange)
                        Text("Video quality reduced due to thermal pressure")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                    .background(Color.orange.opacity(0.1))
                    .cornerRadius(4)
                }

                if pressureMonitor.shouldPauseRecording {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.circle.fill")
                            .foregroundColor(.red)
                        Text("Recording paused - device under critical thermal load")
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                    .background(Color.red.opacity(0.1))
                    .cornerRadius(4)
                }

                if !pressureMonitor.shouldReduceQuality && !pressureMonitor.shouldPauseRecording {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                        Text("System operating normally")
                            .font(.caption)
                            .foregroundColor(.green)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                    .background(Color.green.opacity(0.1))
                    .cornerRadius(4)
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Image(systemName: "info.circle.fill")
                        .foregroundColor(.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("System pressure monitoring")
                            .font(.caption)
                            .foregroundColor(.blue)
                        Text(pressureMonitor.pressureLevel.description)
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
    }
}

#Preview {
    SystemPressureView()
        .preferredColorScheme(.dark)
}
