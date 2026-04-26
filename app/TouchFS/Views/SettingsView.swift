import SwiftUI

struct SettingsView: View {
    let cli: CLIService
    @Binding var screen: AppScreen
    let onImportFiles: ([URL]) -> Void
    @Environment(\.dismiss) var dismiss

    @State private var resetting = false
    @State private var confirmReset = false
    @State private var error: String?

    private let store = FileStore()
    private let mount = MountService.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Settings")
                .font(.title2.bold())

            Divider()

            HStack(alignment: .top, spacing: 30) {
                // Left column
                VStack(alignment: .leading, spacing: 12) {
                    LoginItemToggle()

                    Divider()

                    Text("Import Existing Files")
                        .font(.headline)
                    Text("Find previously sealed files and add them to the app.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button("Find Sealed Files...") {
                        let urls = FilePicker.pickFiles(title: "Select sealed files to import")
                        if !urls.isEmpty {
                            onImportFiles(urls)
                            dismiss()
                        }
                    }

                    Divider()

                    EngineSection(cli: cli, screen: $screen)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                Divider()

                // Right column
                VStack(alignment: .leading, spacing: 12) {
                    CLIInstallSection()

                    Divider()

                    Button("Show Onboarding") {
                        dismiss()
                        screen = .onboarding
                    }

                    Divider()

                    ChangePasswordSection(cli: cli, store: store, mount: mount)

                    Divider()

                    Text("Reset TouchFS")
                        .font(.headline)
                    Text("Unprotects all files, deletes your key, and returns to setup.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    if let error {
                        Text(error)
                            .foregroundStyle(.red)
                            .font(.caption)
                    }

                    if confirmReset {
                        HStack {
                            Text("Are you sure?")
                                .foregroundStyle(.red)
                            Spacer()
                            Button("Cancel") { confirmReset = false }
                            Button(resetting ? "Resetting..." : "Yes, Reset") {
                                Task { await performReset() }
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(.red)
                            .disabled(resetting)
                        }
                    } else {
                        Button("Reset TouchFS...") { confirmReset = true }
                            .foregroundStyle(.red)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Divider()

            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 600)
    }

    private func performReset() async {
        resetting = true
        error = nil

        mount.stop()

        let files = store.load()
        for file in files {
            do {
                try await cli.unseal(path: file.path)
            } catch {
                // Ignore — file might not be sealed or might be missing.
            }
        }

        store.save([])
        do {
            try await cli.reset()
        } catch {}

        // Remove CLI symlink if exists.
        try? FileManager.default.removeItem(atPath: "/usr/local/bin/touchfs")

        resetting = false
        dismiss()
        screen = .onboarding
    }
}
