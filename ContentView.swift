import SwiftUI

struct ContentView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel
    @State private var cameraSetup = false
    @State private var showSettings = false
    @State private var showFiles = false

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

                    // Impact Detection Status
                    if viewModel.isRecording {
                        if viewModel.crashDetected || viewModel.emergencyBrakeDetected {
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

                            Text("Recording Chunk \(viewModel.currentChunkNumber)")
                                .font(.headline)
                                .foregroundColor(.white)

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
            }
        }
            .navigationBarHidden(true)
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
        }
    }
}

#Preview {
    ContentView()
        .environmentObject(CameraDashcamViewModel())
}
