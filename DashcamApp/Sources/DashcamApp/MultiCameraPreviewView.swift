import SwiftUI
import AVFoundation

struct MultiCameraPreviewView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel
    @State private var previewLayers: [CameraPosition: AVCaptureVideoPreviewLayer] = [:]
    @State private var selectedCamera: CameraPosition?
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
                    Text("Multi-Camera Preview")
                        .font(.headline)
                        .foregroundColor(.white)
                    Spacer()
                    Color.clear.frame(width: 44)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 16)
                .borderBottom(Color.gray.opacity(0.2))

                // Camera Grid
                ScrollView {
                    VStack(spacing: 16) {
                        // Camera Status Overview
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Camera Status")
                                .font(.headline)
                                .foregroundColor(.white)

                            VStack(spacing: 8) {
                                ForEach(CameraPosition.allCases, id: \.self) { position in
                                    HStack(spacing: 12) {
                                        let status = viewModel.cameraStatus[position] ?? "Unknown"
                                        let statusColor: Color = status == "Ready" ? .green :
                                                                 status == "Recording" ? .red :
                                                                 .gray

                                        Circle()
                                            .fill(statusColor)
                                            .frame(width: 8, height: 8)

                                        Text(position.rawValue)
                                            .font(.subheadline)
                                            .foregroundColor(.white)
                                            .frame(maxWidth: .infinity, alignment: .leading)

                                        Text(status)
                                            .font(.caption)
                                            .foregroundColor(.gray)
                                    }
                                    .padding(10)
                                    .background(Color.gray.opacity(0.05))
                                    .cornerRadius(8)
                                }
                            }
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Camera Preview Grid
                        VStack(spacing: 12) {
                            Text("Live Preview Feed")
                                .font(.headline)
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity, alignment: .leading)

                            VStack(spacing: 12) {
                                ForEach(CameraPosition.allCases, id: \.self) { position in
                                    CameraPreviewCard(
                                        position: position,
                                        status: viewModel.cameraStatus[position] ?? "Unknown",
                                        isSelected: selectedCamera == position
                                    )
                                    .onTapGesture {
                                        selectedCamera = selectedCamera == position ? nil : position
                                    }
                                }
                            }
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Camera Specifications
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Camera Information")
                                .font(.headline)
                                .foregroundColor(.white)

                            VStack(spacing: 12) {
                                CameraSpecCard(
                                    title: "Back Wide",
                                    specs: [
                                        ("Type", "Wide-angle Camera"),
                                        ("Focal Length", "26mm equivalent"),
                                        ("Resolution", "4K (3840x2160)"),
                                        ("Field of View", "~75°"),
                                        ("Stabilization", "Cinematic")
                                    ]
                                )

                                CameraSpecCard(
                                    title: "Back Zoom",
                                    specs: [
                                        ("Type", "Telephoto Camera"),
                                        ("Focal Length", "77mm equivalent"),
                                        ("Resolution", "Full HD (1920x1080)"),
                                        ("Field of View", "~26°"),
                                        ("Purpose", "License plate capture")
                                    ]
                                )
                            }
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Recording Tips
                        VStack(alignment: .leading, spacing: 12) {
                            HStack(spacing: 8) {
                                Image(systemName: "lightbulb.fill")
                                    .foregroundColor(.yellow)
                                Text("Recording Tips")
                                    .font(.headline)
                                    .foregroundColor(.white)
                            }

                            VStack(alignment: .leading, spacing: 8) {
                                TipRow(icon: "rectangle.fill", text: "Wide camera captures full scene context")
                                TipRow(icon: "magnifyingglass", text: "Zoom camera captures details and plates")
                                TipRow(icon: "video.fill", text: "Both cameras record simultaneously")
                                TipRow(icon: "lock.fill", text: "Protect recordings in accidents automatically")
                            }
                        }
                        .padding(16)
                        .background(Color.blue.opacity(0.1))
                        .cornerRadius(12)
                    }
                    .padding(16)
                }
            }
        }
        .navigationBarHidden(true)
    }
}

struct CameraPreviewCard: View {
    let position: CameraPosition
    let status: String
    let isSelected: Bool

    var body: some View {
        VStack(spacing: 12) {
            // Camera Icon / Placeholder
            VStack(spacing: 8) {
                Image(systemName: position == .backWide ? "camera.aperture" : "magnifyingglass")
                    .font(.system(size: 40))
                    .foregroundColor(.blue)
                    .padding(20)

                Text(position.rawValue)
                    .font(.headline)
                    .foregroundColor(.white)

                Text(status)
                    .font(.caption2)
                    .foregroundColor(status == "Recording" ? .red : .gray)
            }
            .frame(maxWidth: .infinity)
            .frame(height: 160)
            .background(Color.gray.opacity(0.15))
            .cornerRadius(8)

            // Stats
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Resolution")
                        .font(.caption)
                        .foregroundColor(.gray)
                    Text(position == .backWide ? "4K" : "FHD")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(.white)
                }

                Divider()

                VStack(alignment: .leading, spacing: 4) {
                    Text("Frame Rate")
                        .font(.caption)
                        .foregroundColor(.gray)
                    Text("30 fps")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(.white)
                }

                Divider()

                VStack(alignment: .leading, spacing: 4) {
                    Text("Codec")
                        .font(.caption)
                        .foregroundColor(.gray)
                    Text("H.264")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(.white)
                }
            }
            .padding(10)
            .background(Color.gray.opacity(0.05))
            .cornerRadius(6)
        }
        .padding(12)
        .background(isSelected ? Color.blue.opacity(0.2) : Color.gray.opacity(0.1))
        .borderRadius(8, color: isSelected ? Color.blue : Color.clear, width: 2)
        .cornerRadius(8)
    }
}

struct CameraSpecCard: View {
    let title: String
    let specs: [(String, String)]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.subheadline)
                .fontWeight(.semibold)
                .foregroundColor(.blue)

            VStack(alignment: .leading, spacing: 4) {
                ForEach(specs, id: \.0) { key, value in
                    HStack {
                        Text(key)
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
        }
        .padding(10)
        .background(Color.gray.opacity(0.05))
        .cornerRadius(6)
    }
}

struct TipRow: View {
    let icon: String
    let text: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.caption)
                .foregroundColor(.blue)
                .frame(width: 20)

            Text(text)
                .font(.caption)
                .foregroundColor(.gray)
        }
    }
}

extension View {
    func borderRadius(_ radius: CGFloat, color: Color, width: CGFloat) -> some View {
        self
            .overlay(
                RoundedRectangle(cornerRadius: radius)
                    .stroke(color, lineWidth: width)
            )
    }
}

#Preview {
    MultiCameraPreviewView()
        .environmentObject(CameraDashcamViewModel())
}
