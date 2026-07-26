import SwiftUI

@main
struct DashcamApp: App {
    @StateObject private var appearanceManager = AppearanceManager.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(CameraDashcamViewModel())
                .preferredColorScheme(appearanceManager.currentColorScheme)
        }
    }
}
