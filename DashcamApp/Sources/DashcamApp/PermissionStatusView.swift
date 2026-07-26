import SwiftUI

struct PermissionStatusView: View {
    @StateObject private var permissionManager = PermissionStatusManager()
    @EnvironmentObject var viewModel: CameraDashcamViewModel

    var body: some View {
        VStack(spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "lock.shield.fill")
                    .foregroundColor(.blue)
                Text("Permissions Status")
                    .font(.headline)
                    .foregroundColor(.white)
                Spacer()
                if permissionManager.allPermissionsGranted() {
                    HStack(spacing: 4) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                        Text("All Set")
                            .font(.caption)
                            .foregroundColor(.green)
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(Color.blue.opacity(0.1))
            .cornerRadius(8)

            VStack(spacing: 8) {
                PermissionRow(
                    title: "Camera",
                    icon: "camera.fill",
                    status: permissionManager.cameraStatus,
                    onRequest: {
                        permissionManager.requestCameraPermission()
                    },
                    onOpenSettings: {
                        permissionManager.openAppSettings()
                    }
                )

                PermissionRow(
                    title: "Microphone",
                    icon: "mic.fill",
                    status: permissionManager.microphoneStatus,
                    onRequest: {
                        permissionManager.requestMicrophonePermission()
                    },
                    onOpenSettings: {
                        permissionManager.openAppSettings()
                    }
                )

                PermissionRow(
                    title: "Photos",
                    icon: "photo.fill",
                    status: permissionManager.photosStatus,
                    onRequest: {
                        permissionManager.requestPhotosPermission()
                    },
                    onOpenSettings: {
                        permissionManager.openAppSettings()
                    },
                    isOptional: true
                )
            }

            if !permissionManager.allPermissionsGranted() {
                VStack(spacing: 8) {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.orange)
                        Text("Camera and Microphone permissions are required for recording")
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

            if permissionManager.cameraStatus == .notDetermined || permissionManager.microphoneStatus == .notDetermined {
                Button(action: {
                    if permissionManager.cameraStatus == .notDetermined {
                        permissionManager.requestCameraPermission()
                    }
                    if permissionManager.microphoneStatus == .notDetermined {
                        permissionManager.requestMicrophonePermission()
                    }
                }) {
                    HStack {
                        Image(systemName: "checkmark.circle.fill")
                        Text("Request Permissions")
                            .font(.headline)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .foregroundColor(.white)
                    .background(Color.blue)
                    .cornerRadius(8)
                }
            }
        }
        .padding(12)
        .background(Color.gray.opacity(0.1))
        .cornerRadius(8)
        .onAppear {
            permissionManager.updatePermissionStatuses()
        }
    }
}

struct PermissionRow: View {
    let title: String
    let icon: String
    let status: PermissionStatus
    let onRequest: () -> Void
    let onOpenSettings: () -> Void
    var isOptional: Bool = false

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .frame(width: 24)
                .foregroundColor(.white)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(title)
                        .font(.subheadline)
                        .foregroundColor(.white)
                    if isOptional {
                        Text("(optional)")
                            .font(.caption2)
                            .foregroundColor(.gray)
                    }
                }

                Text(status.displayText)
                    .font(.caption)
                    .foregroundColor(status.color)
            }

            Spacer()

            Image(systemName: status.icon)
                .foregroundColor(status.color)
                .font(.system(size: 18))

            if status != .granted {
                Button(action: {
                    if status == .notDetermined {
                        onRequest()
                    } else {
                        onOpenSettings()
                    }
                }) {
                    Text(status == .notDetermined ? "Request" : "Settings")
                        .font(.caption)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(status == .denied ? Color.red.opacity(0.2) : Color.blue.opacity(0.2))
                        .foregroundColor(status == .denied ? .red : .blue)
                        .cornerRadius(4)
                }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Color.gray.opacity(0.05))
        .cornerRadius(6)
    }
}

#Preview {
    PermissionStatusView()
        .environmentObject(CameraDashcamViewModel())
}
