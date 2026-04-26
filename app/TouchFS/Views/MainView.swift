import SwiftUI
import UniformTypeIdentifiers

struct MainView: View {
    let cli: CLIService
    @Binding var screen: AppScreen
    @State private var files: [SealedFile] = []
    @State private var error: String?
    @State private var mountRunning = false
    @State private var showSettings = false

    private let store = FileStore()
    private let mount = MountService.shared

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack {
                Text("Protected Files")
                    .font(.headline)
                Spacer()
                Button { showSettings = true } label: {
                    Image(systemName: "gear")
                }
                .buttonStyle(.plain)
                Button("Protect Files") { openSealPanel() }
                    .buttonStyle(.borderedProminent)
            }
            .padding()

            Divider()

            // Error
            if let error {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.callout)
                    .padding(.horizontal)
                    .padding(.top, 8)
                    .onAppear {
                        Task {
                            try? await Task.sleep(nanoseconds: 5_000_000_000)
                            self.error = nil
                        }
                    }
            }

            // File list
            if files.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "lock.open")
                        .font(.system(size: 40))
                        .foregroundStyle(.secondary)
                    Text("No protected files")
                        .foregroundStyle(.secondary)
                    Text("Use \"Protect Files\" to encrypt files, or find existing ones in Settings")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(files.sorted(by: { $0.path < $1.path })) { file in
                        HStack {
                            Image(systemName: "lock.fill")
                                .foregroundStyle(.green)
                                .font(.caption)
                            Text(file.path)
                                .font(.callout.monospaced())
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer()
                            Button("Unprotect") {
                                Task { await unsealFile(file) }
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(.red)
                            .font(.callout)
                        }
                        .padding(.vertical, 2)
                        .contextMenu {
                            Button("Show in Finder") {
                                NSWorkspace.shared.selectFile(file.path, inFileViewerRootedAtPath: "")
                            }
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
        .onAppear {
            files = store.load()
            startMount()
        }
        .sheet(isPresented: $showSettings) {
            SettingsView(cli: cli, screen: $screen) { urls in
                Task { await findFiles(urls) }
            }
        }
    }

    // MARK: - Mount

    private func startMount() {
        guard !files.isEmpty else { return }
        mount.start(binaryPath: cli.binaryPath, filePaths: files.map(\.path))
        mountRunning = mount.isRunning
    }

    private func restartMount() {
        mount.stop()
        startMount()
    }

    // MARK: - File Pickers

    private func openSealPanel() {
        let urls = FilePicker.pickFiles(title: "Select files to protect")
        guard !urls.isEmpty else { return }
        Task { await sealFiles(urls) }
    }

    // MARK: - Actions

    private func sealFiles(_ urls: [URL]) async {
        error = nil
        var added = 0
        var skipped: [String] = []

        for url in urls {
            let path = url.path

            // Already managed.
            if files.contains(where: { $0.path == path }) {
                skipped.append("\(url.lastPathComponent) (already managed)")
                continue
            }

            // Skip symlinks entirely.
            var s = stat()
            if lstat(path, &s) == 0 && (s.st_mode & S_IFLNK) == S_IFLNK {
                skipped.append("\(url.lastPathComponent) (symlink, skipped)")
                continue
            }

            // Already sealed — suggest importing via Settings.
            if cli.isSealedFile(path: path) {
                skipped.append("\(url.lastPathComponent) is already sealed — use Settings → Find Sealed Files to import it")
                continue
            }

            do {
                try await cli.seal(path: path)
                files.append(SealedFile(path: path))
                added += 1
            } catch {
                skipped.append("\(url.lastPathComponent) (\(error.localizedDescription))")
            }
        }

        if added > 0 {
            store.save(files)
            restartMount()
        }
        if !skipped.isEmpty {
            self.error = "Skipped: \(skipped.joined(separator: ", "))"
        }
    }

    private func findFiles(_ urls: [URL]) async {
        error = nil
        var added = 0
        var skippedUnsealed = 0
        for url in urls {
            if files.contains(where: { $0.path == url.path }) { continue }
            if cli.isSealedFile(path: url.path) {
                files.append(SealedFile(path: url.path))
                added += 1
            } else {
                skippedUnsealed += 1
            }
        }
        if added > 0 {
            store.save(files)
            restartMount()
        }
        if skippedUnsealed > 0 {
            self.error = "Selection contains unsealed files (\(skippedUnsealed) skipped, \(added) imported)"
        } else if added == 0 {
            self.error = "No sealed files found in selection"
        }
    }

    private func unsealFile(_ file: SealedFile) async {
        error = nil
        do {
            // Stop mount first — restores symlinks back to sealed files.
            mount.stop()
            try await cli.unseal(path: file.path)
            files.removeAll { $0.id == file.id }
            store.save(files)
            startMount()
        } catch {
            self.error = error.localizedDescription
            // Restart mount even on failure.
            startMount()
        }
    }
}
