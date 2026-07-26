import SwiftUI
import AVFoundation

struct PiPCameraView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel
    @StateObject private var batteryManager = BatteryMonitorManager.shared
    @State private var position = CGPoint(x: 100, y: 100)
    @State private var isDragging = false
    @State private var dragOffset = CGSize.zero
    @State private var isMinimized = false
    let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Button(action: { isMinimized.toggle() }) {
                    Image(systemName: isMinimized ? "chevron.up" : "chevron.down")
                        .font(.caption)
                        .foregroundColor(.white)
                }

                VStack(alignment: .leading, spacing: 1) {
                    Text("Dashcam")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(.white)
                    HStack(spacing: 4) {
                        Image(systemName: batteryManager.batteryLevel > 0.2 ? "battery.50" : "battery.25")
                            .font(.caption2)
                            .foregroundColor(batteryManager.batteryLevel > 0.2 ? .green : .orange)
                        Text(batteryManager.batteryPercentage)
                            .font(.caption2)
                            .foregroundColor(batteryManager.batteryLevel > 0.2 ? .green : .orange)
                    }
                }

                Spacer()

                if viewModel.isRecording {
                    HStack(spacing: 4) {
                        Circle()
                            .fill(Color.red)
                            .frame(width: 6, height: 6)
                        Text(viewModel.recordingTime)
                            .font(.caption2)
                            .foregroundColor(.red)
                            .monospacedDigit()
                    }
                }

                if viewModel.isRecording {
                    Button(action: {
                        viewModel.protectCurrentChunk()
                    }) {
                        Image(systemName: "lock.circle.fill")
                            .font(.caption)
                            .foregroundColor(.blue)
                    }
                }

                Button(action: {
                    if viewModel.isRecording {
                        viewModel.stopRecording()
                    } else {
                        viewModel.startRecording()
                    }
                }) {
                    Image(systemName: viewModel.isRecording ? "stop.circle.fill" : "record.circle.fill")
                        .font(.caption)
                        .foregroundColor(viewModel.isRecording ? .red : .green)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(Color.black.opacity(0.8))
            .gesture(
                DragGesture()
                    .onChanged { value in
                        isDragging = true
                        dragOffset = value.translation
                    }
                    .onEnded { _ in
                        isDragging = false
                        position.x += dragOffset.width
                        position.y += dragOffset.height
                        dragOffset = .zero
                    }
            )

            if !isMinimized {
                CameraPreviewContainer()
                    .frame(height: 150)
                    .background(Color.black)

                VStack(spacing: 6) {
                    ForEach(CameraPosition.allCases, id: \.self) { camera in
                        HStack(spacing: 8) {
                            Text(camera.rawValue)
                                .font(.caption2)
                                .foregroundColor(.gray)
                            Spacer()
                            Text(viewModel.cameraStatus[camera] ?? "Unknown")
                                .font(.caption2)
                                .foregroundColor(statusColor(for: viewModel.cameraStatus[camera]))
                        }
                        .padding(.horizontal, 8)
                    }
                }
                .padding(.vertical, 6)
                .background(Color.black.opacity(0.6))
            }
        }
        .background(Color.black)
        .cornerRadius(12)
        .shadow(radius: 8)
        .frame(width: 200)
        .offset(x: isDragging ? dragOffset.width : 0, y: isDragging ? dragOffset.height : 0)
        .position(position)
    }

    private func statusColor(for status: String?) -> Color {
        guard let status = status else { return .gray }
        if status.contains("Recording") { return .red }
        if status.contains("Ready") { return .green }
        return .gray
    }
}

struct CameraPreviewContainer: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> CameraPreviewViewController {
        return CameraPreviewViewController()
    }

    func updateUIViewController(_ uiViewController: CameraPreviewViewController, context: Context) {}
}

class CameraPreviewViewController: UIViewController {
    private let previewView = UIView()
    private var previewLayer: AVCaptureVideoPreviewLayer?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.addSubview(previewView)
        previewView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            previewView.topAnchor.constraint(equalTo: view.topAnchor),
            previewView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            previewView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            previewView.trailingAnchor.constraint(equalTo: view.trailingAnchor)
        ])

        guard let device = AVCaptureDevice.default(
            .builtInWideAngleCamera,
            for: .video,
            position: .front
        ) else {
            return
        }

        do {
            let input = try AVCaptureDeviceInput(device: device)
            let session = AVCaptureSession()
            session.sessionPreset = .medium

            if session.canAddInput(input) {
                session.addInput(input)
            }

            let previewLayer = AVCaptureVideoPreviewLayer(session: session)
            previewLayer.videoGravity = .resizeAspectFill
            previewView.layer.addSublayer(previewLayer)
            self.previewLayer = previewLayer

            session.startRunning()
        } catch {
            print("Failed to setup preview: \(error)")
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = previewView.bounds
    }
}

#Preview {
    PiPCameraView()
        .environmentObject(CameraDashcamViewModel())
}
