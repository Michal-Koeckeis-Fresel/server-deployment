import SwiftUI
import AVFoundation

struct LiveCameraFeedView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel
    @Environment(\.dismiss) var dismiss
    @State private var selectedLayout: CameraLayout = .sideBySide

    enum CameraLayout {
        case sideBySide
        case fullScreen
        case pip
    }

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

                    Text("Live Camera Feed")
                        .font(.headline)
                        .foregroundColor(.white)

                    Spacer()

                    Menu {
                        Button(action: { selectedLayout = .sideBySide }) {
                            Label("Side by Side", systemImage: "square.split.2x1")
                        }
                        Button(action: { selectedLayout = .fullScreen }) {
                            Label("Full Screen", systemImage: "square.fill")
                        }
                        Button(action: { selectedLayout = .pip }) {
                            Label("Picture in Picture", systemImage: "pip.fill")
                        }
                    } label: {
                        Image(systemName: "square.and.pencil")
                            .foregroundColor(.white)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 16)
                .borderBottom(Color.gray.opacity(0.2))

                // Camera Feed Display
                Group {
                    switch selectedLayout {
                    case .sideBySide:
                        SideBySideCameraView()
                    case .fullScreen:
                        FullScreenCameraView()
                    case .pip:
                        PiPCameraLayoutView()
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationBarHidden(true)
    }
}

struct SideBySideCameraView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel

    var body: some View {
        VStack(spacing: 2) {
            // Back Wide Camera
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color.gray.opacity(0.2))

                VStack(spacing: 12) {
                    Image(systemName: "camera.aperture")
                        .font(.system(size: 48))
                        .foregroundColor(.blue)

                    Text("Back Wide")
                        .font(.headline)
                        .foregroundColor(.white)

                    HStack(spacing: 16) {
                        VStack(spacing: 4) {
                            Text("Resolution")
                                .font(.caption)
                                .foregroundColor(.gray)
                            Text("4K")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(.white)
                        }

                        Divider()

                        VStack(spacing: 4) {
                            Text("FPS")
                                .font(.caption)
                                .foregroundColor(.gray)
                            Text("30")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(.white)
                        }

                        Divider()

                        VStack(spacing: 4) {
                            Text("Status")
                                .font(.caption)
                                .foregroundColor(.gray)
                            Text(viewModel.cameraStatus[.backWide] ?? "Unknown")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(
                                    (viewModel.cameraStatus[.backWide] ?? "") == "Recording" ? .red : .green
                                )
                        }
                    }
                    .padding(10)
                    .background(Color.gray.opacity(0.05))
                    .cornerRadius(6)
                }
                .padding(20)
            }
            .padding(8)

            // Back Zoom Camera
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color.gray.opacity(0.2))

                VStack(spacing: 12) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 48))
                        .foregroundColor(.purple)

                    Text("Back Zoom")
                        .font(.headline)
                        .foregroundColor(.white)

                    HStack(spacing: 16) {
                        VStack(spacing: 4) {
                            Text("Resolution")
                                .font(.caption)
                                .foregroundColor(.gray)
                            Text("FHD")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(.white)
                        }

                        Divider()

                        VStack(spacing: 4) {
                            Text("FPS")
                                .font(.caption)
                                .foregroundColor(.gray)
                            Text("30")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(.white)
                        }

                        Divider()

                        VStack(spacing: 4) {
                            Text("Status")
                                .font(.caption)
                                .foregroundColor(.gray)
                            Text(viewModel.cameraStatus[.backTelephoto] ?? "Unknown")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundColor(
                                    (viewModel.cameraStatus[.backTelephoto] ?? "") == "Recording" ? .red : .green
                                )
                        }
                    }
                    .padding(10)
                    .background(Color.gray.opacity(0.05))
                    .cornerRadius(6)
                }
                .padding(20)
            }
            .padding(8)
        }
        .padding(8)
    }
}

struct FullScreenCameraView: View {
    @State private var selectedCamera: CameraPosition = .backWide
    @EnvironmentObject var viewModel: CameraDashcamViewModel

    var body: some View {
        VStack(spacing: 12) {
            // Main Camera Display
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color.gray.opacity(0.2))

                VStack(spacing: 12) {
                    Image(
                        systemName: selectedCamera == .backWide ? "camera.aperture" : "magnifyingglass"
                    )
                    .font(.system(size: 64))
                    .foregroundColor(selectedCamera == .backWide ? .blue : .purple)

                    Text(selectedCamera.rawValue)
                        .font(.title2)
                        .fontWeight(.semibold)
                        .foregroundColor(.white)

                    Text("Recording Status: \(viewModel.cameraStatus[selectedCamera] ?? "Unknown")")
                        .font(.caption)
                        .foregroundColor(
                            (viewModel.cameraStatus[selectedCamera] ?? "") == "Recording" ? .red : .green
                        )
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .frame(height: 300)

            // Camera Specs
            VStack(spacing: 10) {
                SpecRow(
                    label: "Resolution",
                    value: selectedCamera == .backWide ? "4K (3840x2160)" : "Full HD (1920x1080)"
                )
                SpecRow(label: "Frame Rate", value: "30 fps")
                SpecRow(
                    label: "Focal Length",
                    value: selectedCamera == .backWide ? "26mm equivalent" : "77mm equivalent"
                )
                SpecRow(
                    label: "Field of View",
                    value: selectedCamera == .backWide ? "~75°" : "~26°"
                )
                SpecRow(label: "Stabilization", value: "Cinematic")
            }
            .padding(12)
            .background(Color.gray.opacity(0.1))
            .cornerRadius(8)

            // Camera Selector
            HStack(spacing: 12) {
                ForEach(CameraPosition.allCases, id: \.self) { position in
                    Button(action: { selectedCamera = position }) {
                        Text(position.rawValue)
                            .font(.caption)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                            .background(selectedCamera == position ? Color.blue : Color.gray.opacity(0.2))
                            .foregroundColor(selectedCamera == position ? .white : .gray)
                            .cornerRadius(6)
                    }
                }
            }

            Spacer()
        }
        .padding(12)
    }
}

struct PiPCameraLayoutView: View {
    @State private var mainCamera: CameraPosition = .backWide
    @EnvironmentObject var viewModel: CameraDashcamViewModel

    var secondaryCamera: CameraPosition {
        mainCamera == .backWide ? .backTelephoto : .backWide
    }

    var body: some View {
        ZStack {
            // Main Camera (Full Screen)
            VStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.gray.opacity(0.2))

                    VStack(spacing: 12) {
                        Image(
                            systemName: mainCamera == .backWide ? "camera.aperture" : "magnifyingglass"
                        )
                        .font(.system(size: 56))
                        .foregroundColor(mainCamera == .backWide ? .blue : .purple)

                        Text(mainCamera.rawValue)
                            .font(.headline)
                            .fontWeight(.semibold)
                            .foregroundColor(.white)

                        Text("Status: \(viewModel.cameraStatus[mainCamera] ?? "Unknown")")
                            .font(.caption)
                            .foregroundColor(
                                (viewModel.cameraStatus[mainCamera] ?? "") == "Recording" ? .red : .green
                            )
                    }
                }

                // Camera Selector Button
                Button(action: { mainCamera = secondaryCamera }) {
                    Text("Switch to \(secondaryCamera.rawValue)")
                        .font(.caption)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(6)
                }
            }
            .padding(12)

            // Picture-in-Picture (Secondary Camera)
            VStack {
                HStack {
                    Spacer()

                    VStack(spacing: 8) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 8)
                                .fill(Color.gray.opacity(0.3))
                                .frame(width: 140, height: 160)

                            VStack(spacing: 8) {
                                Image(
                                    systemName: secondaryCamera == .backWide ? "camera.aperture" : "magnifyingglass"
                                )
                                .font(.system(size: 32))
                                .foregroundColor(secondaryCamera == .backWide ? .blue : .purple)

                                Text(secondaryCamera.rawValue)
                                    .font(.caption)
                                    .fontWeight(.semibold)
                                    .foregroundColor(.white)

                                Text(viewModel.cameraStatus[secondaryCamera] ?? "Unknown")
                                    .font(.caption2)
                                    .foregroundColor(
                                        (viewModel.cameraStatus[secondaryCamera] ?? "") == "Recording" ? .red : .green
                                    )
                            }
                        }
                    }
                    .padding(12)
                }

                Spacer()
            }
        }
    }
}

struct SpecRow: View {
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
    LiveCameraFeedView()
        .environmentObject(CameraDashcamViewModel())
}
