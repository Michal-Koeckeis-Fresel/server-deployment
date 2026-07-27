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
        completion(INStartCallIntentResponse(code: .continueInApp, userActivity: nil))
    }

    private func handleSiriCommand(_ command: String) {
        let normalizedCommand = command.lowercased()

        // Post notification to handle the command - allows it to work across the app
        NotificationCenter.default.post(
            name: NSNotification.Name("DashcamSiriCommand"),
            object: nil,
            userInfo: ["command": normalizedCommand]
        )

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
@MainActor
final class SiriShortcutManager: NSObject, ObservableObject {
    static let shared = SiriShortcutManager()

    @Published var lastCommand: String?
    @Published var commandTimestamp: Date?

    override init() {
        super.init()
        setupObservers()
    }

    private func setupObservers() {
        // Listen for Siri commands posted by DashcamIntentHandler
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleSiriNotification(_:)),
            name: NSNotification.Name("DashcamSiriCommand"),
            object: nil
        )
    }

    @objc private func handleSiriNotification(_ notification: Notification) {
        if let command = notification.userInfo?["command"] as? String {
            self.lastCommand = command
            self.commandTimestamp = Date()
        }
    }

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
            ("Start Dashcam Recording", "dashcam start recording"),
            ("Stop Dashcam Recording", "dashcam stop recording"),
            ("Protect Recording", "dashcam protect recording"),
            ("Dashcam Status", "dashcam status")
        ]

        for (title, command) in commands {
            print("[Siri] Registered voice shortcut: \(title)")
            print("[Siri] Try saying: '\(command)'")
        }
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
}
