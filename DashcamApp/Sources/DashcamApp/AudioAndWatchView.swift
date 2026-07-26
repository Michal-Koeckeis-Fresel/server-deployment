import SwiftUI

struct AudioAndWatchView: View {
    @StateObject private var audioEventDetector = AudioEventDetector.shared
    @State private var watchConnectivityManager: WatchConnectivityManager? = nil

    var body: some View {
        VStack(spacing: 16) {
            // Audio Event Monitoring Status
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Label("Audio Event Monitoring", systemImage: "speaker.wave.3.fill")
                        .font(.headline)
                        .foregroundColor(.white)
                    Spacer()
                }

                VStack(spacing: 10) {
                    HStack {
                        Text("Monitoring Status")
                            .font(.caption)
                            .foregroundColor(.gray)
                        Spacer()
                        Text(audioEventDetector.isMonitoring ? "Active" : "Inactive")
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundColor(audioEventDetector.isMonitoring ? .green : .gray)
                    }

                    Divider()
                        .background(Color.gray.opacity(0.3))

                    HStack {
                        Text("Current Audio Level")
                            .font(.caption)
                            .foregroundColor(.gray)
                        Spacer()
                        Text(audioEventDetector.getFormattedAudioLevel())
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundColor(.white)
                    }

                    HStack {
                        Text("Peak Audio Level")
                            .font(.caption)
                            .foregroundColor(.gray)
                        Spacer()
                        Text(audioEventDetector.getPeakAudioLevelString())
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundColor(.blue)
                    }

                    HStack {
                        Text("Events Detected")
                            .font(.caption)
                            .foregroundColor(.gray)
                        Spacer()
                        Text("\(audioEventDetector.getAudioEventHistory().count)")
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundColor(.white)
                    }
                }

                HStack(spacing: 8) {
                    Image(systemName: "info.circle.fill")
                        .foregroundColor(.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Detects")
                            .font(.caption2)
                            .fontWeight(.semibold)
                            .foregroundColor(.blue)
                        Text("Airbag deployment, glass breaking, sudden impacts, and loud noises")
                            .font(.caption2)
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

            // Audio Event History
            if !audioEventDetector.getAudioEventHistory().isEmpty {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Label("Recent Audio Events", systemImage: "list.bullet")
                            .font(.headline)
                            .foregroundColor(.white)
                        Spacer()
                    }

                    VStack(spacing: 8) {
                        ForEach(audioEventDetector.getAudioEventHistory().suffix(5).reversed(), id: \.timestamp) { event in
                            HStack(spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(event.type.rawValue)
                                        .font(.caption)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.white)
                                    Text(event.timestamp.formatted(date: .omitted, time: .standard))
                                        .font(.caption2)
                                        .foregroundColor(.gray)
                                }

                                Spacer()

                                VStack(alignment: .trailing, spacing: 2) {
                                    Text("\(String(format: "%.1f", event.audioLevel)) dB")
                                        .font(.caption2)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.blue)
                                    if let freq = event.frequency {
                                        Text("\(freq) Hz")
                                            .font(.caption2)
                                            .foregroundColor(.gray)
                                    }
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
            }

            // Apple Watch Connectivity
            if #available(iOS 14.0, *) {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Label("Apple Watch Connection", systemImage: "applewatch.fill")
                            .font(.headline)
                            .foregroundColor(.white)
                        Spacer()
                    }

                    VStack(spacing: 10) {
                        if let manager = watchConnectivityManager {
                            HStack {
                                Text("Paired")
                                    .font(.caption)
                                    .foregroundColor(.gray)
                                Spacer()
                                HStack(spacing: 6) {
                                    Circle()
                                        .fill(manager.isWatchPaired ? Color.green : Color.gray)
                                        .frame(width: 8, height: 8)
                                    Text(manager.isWatchPaired ? "Yes" : "No")
                                        .font(.caption)
                                        .fontWeight(.semibold)
                                        .foregroundColor(manager.isWatchPaired ? .green : .gray)
                                }
                            }

                            Divider()
                                .background(Color.gray.opacity(0.3))

                            HStack {
                                Text("Reachable")
                                    .font(.caption)
                                    .foregroundColor(.gray)
                                Spacer()
                                HStack(spacing: 6) {
                                    Circle()
                                        .fill(manager.isWatchReachable ? Color.green : Color.orange)
                                        .frame(width: 8, height: 8)
                                    Text(manager.isWatchReachable ? "Connected" : "Not Connected")
                                        .font(.caption)
                                        .fontWeight(.semibold)
                                        .foregroundColor(manager.isWatchReachable ? .green : .orange)
                                }
                            }

                            Divider()
                                .background(Color.gray.opacity(0.3))

                            HStack {
                                Text("Alerts Sent")
                                    .font(.caption)
                                    .foregroundColor(.gray)
                                Spacer()
                                Text("\(manager.getAlertHistory().count)")
                                    .font(.caption)
                                    .fontWeight(.semibold)
                                    .foregroundColor(.white)
                            }

                            if let lastSent = manager.lastMessageSent {
                                Divider()
                                    .background(Color.gray.opacity(0.3))

                                HStack {
                                    Text("Last Message")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Spacer()
                                    Text(lastSent.formatted(date: .omitted, time: .standard))
                                        .font(.caption)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.white)
                                }
                            }
                        } else {
                            Text("Initializing Watch Connection...")
                                .font(.caption)
                                .foregroundColor(.gray)
                        }
                    }

                    HStack(spacing: 8) {
                        Image(systemName: "info.circle.fill")
                            .foregroundColor(.green)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Watch Alerts")
                                .font(.caption2)
                                .fontWeight(.semibold)
                                .foregroundColor(.green)
                            Text("Critical events are sent to your Apple Watch: crashes, airbag detection, emergency braking, parking motion")
                                .font(.caption2)
                                .foregroundColor(.green)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(Color.green.opacity(0.1))
                    .cornerRadius(6)
                }
                .padding(16)
                .background(Color.gray.opacity(0.1))
                .cornerRadius(12)
            }
        }
        .onAppear {
            if #available(iOS 14.0, *) {
                if watchConnectivityManager == nil {
                    watchConnectivityManager = WatchConnectivityManager.shared
                }
            }
        }
    }
}

#Preview {
    ScrollView {
        AudioAndWatchView()
            .padding(16)
    }
    .background(Color.black)
}
