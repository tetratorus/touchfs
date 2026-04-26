import SwiftUI
import UniformTypeIdentifiers

struct MainView: View {
    let cli: CLIService
    @State private var files: [SealedFile] = []
    @State private var error: String?
    @State private var showSettings = false
    @State private var showWelcome = false
    @State private var needsInstall = false
    @State private var needsPassword = false
    @State private var installing = false
    @State private var installProgress = ""
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var settingPassword = false

    private let store = FileStore()
    private let mount = MountService.shared

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack {
                Text("TouchFS")
                    .font(.headline)
                Spacer()
                Button { showSettings = true } label: {
                    Image(systemName: "gear")
                }
                .buttonStyle(.plain)
                .disabled(needsInstall)
                Button("Protect Files") { openSealPanel() }
                    .buttonStyle(.borderedProminent)
                    .disabled(needsInstall || needsPassword)
                    .opacity(needsInstall || needsPassword ? 0.4 : 1.0)
            }
            .padding()

            Divider()

            // Banners
            if needsInstall {
                installBanner
            } else if needsPassword {
                passwordBanner
            } else if showWelcome {
                welcomeBanner
            }

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
            if !needsInstall && !needsPassword && !showWelcome {
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
                } else if !files.isEmpty {
                    fileList
                }
            }
        }
        .onAppear { checkState() }
        .sheet(isPresented: $showSettings) {
            SettingsView(cli: cli, onShowWelcome: { showWelcome = true }) { urls in
                Task { await findFiles(urls) }
            }
        }
    }

    // MARK: - Banners

    private var installBanner: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "arrow.down.circle.fill")
                .font(.system(size: 48))
                .foregroundStyle(.blue)
            Text("Setup Required")
                .font(.title2.bold())
            VStack(spacing: 4) {
                if !cli.hasBinary {
                    Text("TouchFS encryption engine not found")
                        .foregroundStyle(.secondary)
                }
                if !cli.hasFuseT {
                    Text("fuse-t (filesystem driver) not found")
                        .foregroundStyle(.secondary)
                }
            }
            if installing {
                ProgressView(installProgress)
            } else {
                Button("Install") {
                    Task { await doInstall() }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var passwordBanner: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "key.fill")
                .font(.system(size: 48))
                .foregroundStyle(.orange)
            Text("Set a Password")
                .font(.title2.bold())
            Text("This password derives an encryption key stored in your Mac's Keychain.\nAfter this, you'll only need Touch ID.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 400)
            VStack(spacing: 8) {
                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                SecureField("Confirm password", text: $confirmPassword)
                    .textFieldStyle(.roundedBorder)
            }
            .frame(maxWidth: 300)
            Button(settingPassword ? "Saving..." : "Continue") {
                Task { await setPassword() }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(password.isEmpty || settingPassword)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var welcomeBanner: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 48))
                .foregroundStyle(.blue)
            Text("TouchFS")
                .font(.title.bold())
            Text("Protect your sensitive files with Touch ID encryption.\nAI editors, scripts, and apps can't read them without your fingerprint.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 400)
            Button("Got it") { showWelcome = false }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - File List

    private var fileList: some View {
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
                    .buttonStyle(.bordered)
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

    // MARK: - State

    private func checkState() {
        files = store.load()
        Task {
            var ready = cli.hasBinary && cli.hasFuseT
            if ready { ready = await cli.checkBinaryWorks() }
            if !ready {
                needsInstall = true
                return
            }
            needsInstall = false
            if files.isEmpty {
                if let status = try? await cli.status(), status.hasKey {
                    needsPassword = false
                } else {
                    needsPassword = true
                    showWelcome = true
                }
            } else {
                needsPassword = false
                if !mount.isRunning {
                    startMount()
                }
            }
        }
    }

    // MARK: - Install

    private func doInstall() async {
        installing = true
        error = nil
        do {
            try await Installer.install { msg in installProgress = msg }
            installing = false
            needsInstall = false
            checkState()
        } catch {
            self.error = error.localizedDescription
            installing = false
        }
    }

    // MARK: - Password

    private func setPassword() async {
        error = nil
        guard password == confirmPassword else {
            error = "Passwords don't match"
            return
        }
        settingPassword = true
        do {
            try await cli.setPassword(password)
            needsPassword = false
            showWelcome = false
            password = ""
            confirmPassword = ""
        } catch {
            self.error = error.localizedDescription
        }
        settingPassword = false
    }

    // MARK: - Mount

    private func startMount() {
        guard !files.isEmpty else { return }
        mount.start(binaryPath: cli.binaryPath, filePaths: files.map(\.path))
    }

    private func restartMount() {
        mount.stop()
        startMount()
    }

    // MARK: - File Actions

    private func openSealPanel() {
        let urls = FilePicker.pickFiles(title: "Select files to protect")
        guard !urls.isEmpty else { return }
        Task { await sealFiles(urls) }
    }

    private func sealFiles(_ urls: [URL]) async {
        error = nil
        var added = 0
        var skipped: [String] = []

        for url in urls {
            let path = url.path

            if files.contains(where: { $0.path == path }) {
                skipped.append("\(url.lastPathComponent) (already managed)")
                continue
            }

            var s = stat()
            if lstat(path, &s) == 0 && (s.st_mode & S_IFLNK) == S_IFLNK {
                skipped.append("\(url.lastPathComponent) (symlink, skipped)")
                continue
            }

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
        mount.stop()
        do {
            try await cli.unseal(path: file.path)
        } catch {
            print("Unseal failed for \(file.path): \(error). Removing from config.")
        }
        files.removeAll { $0.id == file.id }
        store.save(files)
        startMount()
    }
}
