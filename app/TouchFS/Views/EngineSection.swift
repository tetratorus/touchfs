import SwiftUI

struct EngineSection: View {
    let cli: CLIService
    @Binding var screen: AppScreen

    @State private var version = ""
    @State private var updating = false
    @State private var progress = ""
    @State private var error: String?
    @State private var confirmUninstall = false

    var body: some View {
        Text("Encryption Engine")
            .font(.headline)
            .task {
                if let v = try? await cli.version() {
                    version = v
                }
            }

        if !version.isEmpty {
            Text("Installed: \(version)")
                .font(.caption)
                .foregroundStyle(.secondary)
        }

        if let error {
            Text(error)
                .foregroundStyle(.red)
                .font(.caption)
        }

        if updating {
            ProgressView(progress)
                .font(.caption)
        } else {
            HStack(spacing: 12) {
                Button("Check for Update") {
                    Task { await update() }
                }

                if confirmUninstall {
                    Button("Cancel") { confirmUninstall = false }
                    Button("Confirm Uninstall") {
                        uninstall()
                    }
                    .foregroundStyle(.red)
                } else {
                    Button("Uninstall") { confirmUninstall = true }
                        .foregroundStyle(.red)
                }
            }
        }
    }

    private func update() async {
        updating = true
        error = nil
        do {
            try await Installer.install { msg in
                progress = msg
            }
            // Refresh version.
            if let v = try? await cli.version() {
                version = v
            }
            progress = "Updated to \(version)"
        } catch {
            self.error = error.localizedDescription
        }
        updating = false
    }

    private func uninstall() {
        error = nil
        do {
            try FileManager.default.removeItem(atPath: "/Applications/touchfs.app")
            confirmUninstall = false
            screen = .install
        } catch {
            self.error = "Failed to uninstall: \(error.localizedDescription)"
            confirmUninstall = false
        }
    }
}

