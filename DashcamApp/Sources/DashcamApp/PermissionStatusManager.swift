import AVFoundation
import Photos
import SwiftUI

enum PermissionStatus: Equatable {
    case granted
    case denied
    case notDetermined

    var displayText: String {
        switch self {
        case .granted:
            return "Granted"
        case .denied:
            return "Denied"
        case .notDetermined:
            return "Not Yet Requested"
        }
    }

    var icon: String {
        switch self {
        case .granted:
            return "checkmark.circle.fill"
        case .denied:
            return "xmark.circle.fill"
        case .notDetermined:
            return "questionmark.circle.fill"
        }
    }

    var color: Color {
        switch self {
        case .granted:
            return .green
        case .denied:
            return .red
        case .notDetermined:
            return .orange
        }
    }
}

class PermissionStatusManager: ObservableObject {
    @Published var cameraStatus: PermissionStatus = .notDetermined
    @Published var microphoneStatus: PermissionStatus = .notDetermined
    @Published var photosStatus: PermissionStatus = .notDetermined

    init() {
        updatePermissionStatuses()
    }

    func updatePermissionStatuses() {
        cameraStatus = checkCameraPermission()
        microphoneStatus = checkMicrophonePermission()
        photosStatus = checkPhotosPermission()
    }

    private func checkCameraPermission() -> PermissionStatus {
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        switch status {
        case .authorized:
            return .granted
        case .denied, .restricted:
            return .denied
        case .notDetermined:
            return .notDetermined
        @unknown default:
            return .notDetermined
        }
    }

    private func checkMicrophonePermission() -> PermissionStatus {
        let status = AVAudioSession.sharedInstance().recordPermission
        switch status {
        case .granted:
            return .granted
        case .denied:
            return .denied
        case .undetermined:
            return .notDetermined
        @unknown default:
            return .notDetermined
        }
    }

    private func checkPhotosPermission() -> PermissionStatus {
        let status = PHPhotoLibrary.authorizationStatus(for: .addOnly)
        switch status {
        case .authorized:
            return .granted
        case .denied, .restricted:
            return .denied
        case .notDetermined:
            return .notDetermined
        case .limited:
            return .granted
        @unknown default:
            return .notDetermined
        }
    }

    func requestCameraPermission() {
        AVCaptureDevice.requestAccess(for: .video) { _ in
            DispatchQueue.main.async {
                self.updatePermissionStatuses()
            }
        }
    }

    func requestMicrophonePermission() {
        AVAudioSession.sharedInstance().requestRecordPermission { _ in
            DispatchQueue.main.async {
                self.updatePermissionStatuses()
            }
        }
    }

    func requestPhotosPermission() {
        PHPhotoLibrary.requestAuthorization(for: .addOnly) { _ in
            DispatchQueue.main.async {
                self.updatePermissionStatuses()
            }
        }
    }

    func allPermissionsGranted() -> Bool {
        return cameraStatus == .granted && microphoneStatus == .granted
    }

    func openAppSettings() {
        guard let settingsURL = URL(string: UIApplication.openSettingsURLString) else {
            return
        }
        UIApplication.shared.open(settingsURL)
    }
}
