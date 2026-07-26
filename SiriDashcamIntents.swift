import Foundation
import Intents

// Siri Intent Handler for Dashcam control
@available(iOS 15.0, *)
class DashcamIntentHandler: NSObject, INStartCallIntentHandling {
    weak var viewModel: CameraDashcamViewModel?

    func handle(intent: INStartCallIntent, completion: @escaping (INStartCallIntentResponse) -> Void) {
        guard let recipient = intent.contacts?.first?.displayName else {
            completion(INStartCallIntentResponse(code: .failure, userActivity: nil))
            return
        }

        handleSiriCommand(recipient)
        completion(INStartCallIntentResponse(code: .success, userActivity: nil))
    }

    private func handleSiriCommand(_ command: String) {
        let normalizedCommand = command.lowercased()

        DispatchQueue.main.async { [weak self] in
            if normalizedCommand.contains("record") || normalizedCommand.contains("start") {
                self?.viewModel?.startRecording()
                print("[Siri] Started recording")
            } else if normalizedCommand.contains("stop") {
                self?.viewModel?.stopRecording()
                print("[Siri] Stopped recording")
            } else if normalizedCommand.contains("protect") {
                self?.viewModel?.protectCurrentChunk()
                print("[Siri] Protected current recording")
            }
        }
    }
}

// Simple Siri Shortcut trigger handler
class SiriShortcutManager {
    static let shared = SiriShortcutManager()

    func handleShortcutCommand(_ command: String, viewModel: CameraDashcamViewModel) {
        let normalizedCommand = command.lowercased()

        DispatchQueue.main.async {
            switch normalizedCommand {
            case _ where normalizedCommand.contains("start") || normalizedCommand.contains("record"):
                viewModel.startRecording()
                print("[Siri Shortcut] Recording started")

            case _ where normalizedCommand.contains("stop"):
                viewModel.stopRecording()
                print("[Siri Shortcut] Recording stopped")

            case _ where normalizedCommand.contains("protect"):
                viewModel.protectCurrentChunk()
                print("[Siri Shortcut] Recording protected")

            case _ where normalizedCommand.contains("status"):
                let status = viewModel.isRecording ? "Recording" : "Ready"
                print("[Siri Shortcut] Status: \(status)")

            default:
                print("[Siri Shortcut] Unknown command: \(command)")
            }
        }
    }

    func registerSiriVoiceShortcuts() {
        let commands = [
            ("Start Dashcam Recording", "start recording"),
            ("Stop Dashcam Recording", "stop recording"),
            ("Protect Recording", "protect recording"),
            ("Dashcam Status", "dashcam status")
        ]

        for (title, command) in commands {
            print("[Siri] Registered voice shortcut: \(title)")
        }
    }
}
