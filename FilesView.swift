import SwiftUI

struct FilesView: View {
    @EnvironmentObject var viewModel: CameraDashcamViewModel
    @Environment(\.dismiss) var dismiss
    @State private var files: [URL] = []
    @State private var selectedFile: URL?
    @State private var showDeleteConfirm = false
    @State private var refreshTrigger = false

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
                    Text("Recordings")
                        .font(.headline)
                        .foregroundColor(.white)
                    Spacer()
                    Button(action: { refreshFiles() }) {
                        Image(systemName: "arrow.clockwise")
                            .foregroundColor(.blue)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 16)
                .borderBottom(Color.gray.opacity(0.2))

                if files.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "film")
                            .font(.system(size: 48))
                            .foregroundColor(.gray)
                        Text("No Recordings")
                            .font(.headline)
                            .foregroundColor(.white)
                        Text("Start recording to save videos")
                            .font(.caption)
                            .foregroundColor(.gray)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Color.black)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 12) {
                            ForEach(files, id: \.self) { file in
                                FileRowView(
                                    file: file,
                                    isProtected: viewModel.isFileProtected(url: file),
                                    onToggleProtect: {
                                        viewModel.toggleFileProtection(for: file)
                                        refreshFiles()
                                    },
                                    onDelete: {
                                        selectedFile = file
                                        showDeleteConfirm = true
                                    }
                                )
                            }
                        }
                        .padding(20)
                    }
                }
            }
        }
        .alert("Delete Recording?", isPresented: $showDeleteConfirm) {
            Button("Cancel", role: .cancel) { }
            Button("Delete", role: .destructive) {
                if let file = selectedFile {
                    viewModel.deleteFile(at: file)
                    refreshFiles()
                    selectedFile = nil
                }
            }
        } message: {
            if let file = selectedFile {
                Text("This will permanently delete \(file.lastPathComponent)")
            }
        }
        .onAppear {
            refreshFiles()
        }
        .onChange(of: refreshTrigger) { _ in
            refreshFiles()
        }
    }

    private func refreshFiles() {
        files = viewModel.getRecordedFiles()
    }
}

struct FileRowView: View {
    let file: URL
    let isProtected: Bool
    let onToggleProtect: () -> Void
    let onDelete: () -> Void

    var body: some View {
        VStack(spacing: 12) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(file.lastPathComponent)
                        .font(.subheadline)
                        .foregroundColor(.white)
                        .lineLimit(1)

                    HStack(spacing: 8) {
                        Text(formattedFileSize())
                            .font(.caption)
                            .foregroundColor(.gray)

                        Text("•")
                            .foregroundColor(.gray)

                        Text(formattedDate())
                            .font(.caption)
                            .foregroundColor(.gray)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                VStack(spacing: 8) {
                    Button(action: onToggleProtect) {
                        Image(systemName: isProtected ? "lock.fill" : "lock.open")
                            .font(.system(size: 16))
                            .frame(width: 36, height: 36)
                            .background(Color.gray.opacity(0.2))
                            .foregroundColor(isProtected ? .yellow : .gray)
                            .cornerRadius(8)
                    }

                    Button(action: onDelete) {
                        Image(systemName: "trash")
                            .font(.system(size: 16))
                            .frame(width: 36, height: 36)
                            .background(Color.red.opacity(0.2))
                            .foregroundColor(.red)
                            .cornerRadius(8)
                    }
                    .opacity(isProtected ? 0.5 : 1.0)
                    .disabled(isProtected)
                }
            }
            .padding(12)
            .background(Color.gray.opacity(0.1))
            .cornerRadius(10)
        }
    }

    private func formattedFileSize() -> String {
        do {
            let resources = try file.resourceValues(forKeys: [.fileSizeKey])
            let bytes = resources.fileSize ?? 0
            let mb = Double(bytes) / (1024 * 1024)
            return String(format: "%.1f MB", mb)
        } catch {
            return "Unknown"
        }
    }

    private func formattedDate() -> String {
        do {
            let resources = try file.resourceValues(forKeys: [.contentModificationDateKey])
            if let date = resources.contentModificationDate {
                let formatter = DateFormatter()
                formatter.dateStyle = .short
                formatter.timeStyle = .short
                return formatter.string(from: date)
            }
        } catch { }
        return "Unknown"
    }
}

#Preview {
    FilesView()
        .environmentObject(CameraDashcamViewModel())
}
