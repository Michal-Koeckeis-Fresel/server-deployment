import SwiftUI

struct AppearanceView: View {
    @StateObject private var appearanceManager = AppearanceManager.shared
    @State private var selectedMode = AppearanceManager.shared.selectedMode

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Appearance", systemImage: "paintbrush.fill")
                    .font(.headline)
                    .foregroundColor(.white)
                Spacer()
                Text(appearanceManager.selectedMode.rawValue)
                    .font(.headline)
                    .foregroundColor(.blue)
            }

            VStack(spacing: 10) {
                ForEach(AppearanceMode.allCases, id: \.self) { mode in
                    Button(action: {
                        appearanceManager.selectedMode = mode
                        selectedMode = mode
                    }) {
                        HStack(spacing: 12) {
                            Image(systemName: mode.icon)
                                .font(.system(size: 16))
                                .foregroundColor(.white)
                                .frame(width: 24)

                            VStack(alignment: .leading, spacing: 4) {
                                Text(mode.rawValue)
                                    .font(.subheadline)
                                    .foregroundColor(.white)
                                Text(mode.description)
                                    .font(.caption)
                                    .foregroundColor(.gray)
                            }
                            Spacer()
                            if appearanceManager.selectedMode == mode {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.blue)
                            }
                        }
                        .padding(12)
                        .background(appearanceManager.selectedMode == mode ? Color.blue.opacity(0.1) : Color.gray.opacity(0.05))
                        .cornerRadius(8)
                    }
                    .foregroundColor(.primary)
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Image(systemName: "info.circle.fill")
                        .foregroundColor(.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Theme preference")
                            .font(.caption)
                            .foregroundColor(.blue)
                        Text("Choose your preferred appearance. System mode follows your device settings.")
                            .font(.caption2)
                            .foregroundColor(.blue)
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color.blue.opacity(0.1))
            .cornerRadius(6)
        }
        .padding(16)
        .background(Color.gray.opacity(0.1))
        .cornerRadius(12)
    }
}

#Preview {
    AppearanceView()
        .preferredColorScheme(.dark)
        .padding()
}
