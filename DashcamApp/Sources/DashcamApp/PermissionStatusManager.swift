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
        print("[Permissions] Checking all permissions...")
        cameraStatus = checkCameraPermission()
        microphoneStatus = checkMicrophonePermission()
        photosStatus = checkPhotosPermission()
        print("[Permissions] Camera: \(cameraStatus.displayText), Microphone: \(microphoneStatus.displayText), Photos: \(photosStatus.displayText)")
    }

    private func checkCameraPermission() -> PermissionStatus {
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        print("[Permissions] Camera permission status: \(status.rawValue)")
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
        let status = AVAudioApplication.shared.recordPermission
        print("[Permissions] Microphone permission status: \(status.rawValue)")
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
        print("[Permissions] Photos permission status: \(status.rawValue)")
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
        print("[Permissions] Requesting camera permission...")
        AVCaptureDevice.requestAccess(for: .video) { granted in
            print("[Permissions] Camera permission result: \(granted ? "GRANTED" : "DENIED")")
            DispatchQueue.main.async {
                self.updatePermissionStatuses()
            }
        }
    }

    func requestMicrophonePermission() {
        print("[Permissions] Requesting microphone permission...")
        AVAudioApplication.requestRecordPermission { granted in
            print("[Permissions] Microphone permission result: \(granted ? "GRANTED" : "DENIED")")
            DispatchQueue.main.async {
                self.updatePermissionStatuses()
            }
        }
    }

    func requestPhotosPermission() {
        print("[Permissions] Requesting photos permission...")
        PHPhotoLibrary.requestAuthorization(for: .addOnly) { status in
            print("[Permissions] Photos permission result: \(status.rawValue)")
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
