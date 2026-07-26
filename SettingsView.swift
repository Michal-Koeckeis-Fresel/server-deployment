import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel
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
                    Text("Settings")
                        .font(.headline)
                        .foregroundColor(.white)
                    Spacer()
                    Color.clear.frame(width: 44)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 16)
                .borderBottom(Color.gray.opacity(0.2))

                ScrollView {
                    VStack(spacing: 24) {
                        // Video Chunk Duration
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Video Chunk Duration", systemImage: "film.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                                Text("\(viewModel.chunkDurationMinutes) min")
                                    .font(.headline)
                                    .foregroundColor(.blue)
                            }

                            VStack(spacing: 8) {
                                Slider(
                                    value: Double(viewModel.chunkDurationMinutes),
                                    in: 1...15,
                                    step: 1
                                ) { _ in } onEditingChanged: { _ in
                                    // Update happens via didSet
                                }
                                .tint(.blue)

                                HStack(spacing: 20) {
                                    Text("1 min")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Spacer()
                                    Text("15 min")
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                }
                            }

                            Text("Videos will automatically split into chunks. Smaller chunks use less storage per file.")
                                .font(.caption)
                                .foregroundColor(.gray)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Maximum Storage
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Maximum Storage", systemImage: "internaldrive.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                                Text(String(format: "%.0f GB", viewModel.maxStorageGB))
                                    .font(.headline)
                                    .foregroundColor(.blue)
                            }

                            VStack(spacing: 12) {
                                HStack(spacing: 12) {
                                    ForEach([5.0, 10.0, 20.0, 50.0], id: \.self) { gb in
                                        Button(action: { viewModel.maxStorageGB = gb }) {
                                            Text(String(format: "%.0f GB", gb))
                                                .font(.caption)
                                                .frame(maxWidth: .infinity)
                                                .padding(.vertical, 8)
                                                .background(viewModel.maxStorageGB == gb ? Color.blue : Color.gray.opacity(0.2))
                                                .foregroundColor(viewModel.maxStorageGB == gb ? .white : .gray)
                                                .cornerRadius(8)
                                        }
                                    }
                                }

                                VStack(spacing: 6) {
                                    HStack {
                                        Text("Custom:")
                                            .font(.caption)
                                            .foregroundColor(.gray)
                                        Spacer()
                                        Text(String(format: "%.1f GB", viewModel.maxStorageGB))
                                            .font(.caption)
                                            .foregroundColor(.white)
                                    }
                                    Slider(
                                        value: $viewModel.maxStorageGB,
                                        in: 1...100,
                                        step: 0.5
                                    )
                                    .tint(.blue)
                                }
                            }

                            Text("Old unprotected videos are automatically deleted when storage limit is reached.")
                                .font(.caption)
                                .foregroundColor(.gray)
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        // Current Storage Info
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Current Storage Usage", systemImage: "chart.pie.fill")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Spacer()
                            }

                            VStack(spacing: 12) {
                                ProgressView(value: min(viewModel.currentStorageGB / viewModel.maxStorageGB, 1.0))
                                    .tint(.blue)

                                HStack {
                                    Text(String(format: "%.2f GB used", viewModel.currentStorageGB))
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                    Spacer()
                                    Text(String(format: "%.2f GB available", max(0, viewModel.maxStorageGB - viewModel.currentStorageGB)))
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                }
                            }
                        }
                        .padding(16)
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(12)

                        Spacer()
                    }
                    .padding(20)
                }
            }
        }
    }
}

extension View {
    func borderBottom(_ color: Color) -> some View {
        VStack {
            self
            Divider()
                .background(color)
        }
    }
}

#Preview {
    SettingsView()
        .environmentObject(CameraDashcamViewModel())
}
