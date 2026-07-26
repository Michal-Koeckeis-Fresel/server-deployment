import SwiftUI

struct ContentView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel
    @State private var cameraSetup = false

    var body: some View {
        ZStack {
            // Background
            Color.black.ignoresSafeArea()

            VStack(spacing: 24) {
                // Header
                VStack(alignment: .leading, spacing: 8) {
                    Text("Dashcam")
                        .font(.system(size: 32, weight: .bold))
                        .foregroundColor(.white)

                    Text(viewModel.isRecording ? "Recording..." : "Ready")
                        .font(.subheadline)
                        .foregroundColor(viewModel.isRecording ? .red : .gray)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)
                .padding(.top, 16)

                Spacer()

                // Timer Display
                VStack(spacing: 12) {
                    if viewModel.isRecording {
                        HStack(spacing: 12) {
                            Circle()
                                .fill(Color.red)
                                .frame(width: 16, height: 16)
                                .opacity(0.7)

                            Text("Recording")
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
        .onAppear {
            if !cameraSetup {
                viewModel.setupCamera()
                cameraSetup = true
            }
        }
    }
}

#Preview {
    ContentView()
        .environmentObject(CameraDashcamViewModel())
}
