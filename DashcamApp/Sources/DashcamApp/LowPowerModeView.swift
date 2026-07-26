import SwiftUI

struct LowPowerModeView: View {
    @StateObject private var powerModeMonitor = LowPowerModeMonitor.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Low Power Mode", systemImage: "bolt.slash.fill")
                    .font(.headline)
                    .foregroundColor(.white)
                Spacer()
                HStack(spacing: 4) {
                    Image(systemName: powerModeMonitor.isLowPowerModeEnabled ? "bolt.slash.fill" : "bolt.fill")
                        .foregroundColor(powerModeMonitor.isLowPowerModeEnabled ? .orange : .green)
                    Text(powerModeMonitor.powerStateDescription)
                        .font(.headline)
                        .foregroundColor(powerModeMonitor.isLowPowerModeEnabled ? .orange : .green)
                }
            }

            VStack(spacing: 8) {
                HStack {
                    Text("Status")
                        .font(.caption)
                        .foregroundColor(.gray)
                    Spacer()
                    Text(powerModeMonitor.statusMessage)
                        .font(.caption)
                        .foregroundColor(.white)
                }

                HStack {
                    Text("Video Frame Rate")
                        .font(.caption)
                        .foregroundColor(.gray)
                    Spacer()
                    Text("\(powerModeMonitor.recommendedFrameRate) fps")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(powerModeMonitor.isLowPowerModeEnabled ? .orange : .green)
                }

                HStack {
                    Text("Video Quality")
                        .font(.caption)
                        .foregroundColor(.gray)
                    Spacer()
                    Text(powerModeMonitor.shouldReduceQuality ? "Reduced" : "Full")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(powerModeMonitor.isLowPowerModeEnabled ? .orange : .green)
                }
            }

            VStack(spacing: 6) {
                if powerModeMonitor.isLowPowerModeEnabled {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Battery Saving Active")
                                .font(.caption)
                                .foregroundColor(.orange)
                            Text("Video quality and frame rate reduced to extend battery life")
                                .font(.caption2)
                                .foregroundColor(.orange)
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                    .background(Color.orange.opacity(0.1))
                    .cornerRadius(4)
                } else {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                        Text("Full quality recording available")
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
                        Text("Low Power Mode optimization")
                            .font(.caption)
                            .foregroundColor(.blue)
                        Text("Reduces CPU/GPU load to extend battery life during extended recording sessions")
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
    LowPowerModeView()
        .preferredColorScheme(.dark)
}
