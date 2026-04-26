import SwiftUI

struct InstallView: View {
    @Binding var screen: AppScreen
    let cli: CLIService

    @State private var installing = false
    @State private var progress = ""
    @State private var error: String?

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "arrow.down.circle.fill")
                .font(.system(size: 64))
                .foregroundStyle(.blue)

            Text("Setup Required")
                .font(.largeTitle.bold())

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
                ProgressView(progress)
            } else {
                if let error {
                    Text(error)
                        .foregroundStyle(.red)
                        .font(.callout)
                }

                Button("Install") {
                    Task { await doInstall() }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func doInstall() async {
        installing = true
        error = nil
        do {
            try await Installer.install { msg in
                progress = msg
            }
            // Verify it worked.
            if cli.isInstalled {
                // Continue to status check → onboarding or main.
                do {
                    let status = try await cli.status()
                    screen = status.hasKey ? .main : .onboarding
                } catch {
                    screen = .onboarding
                }
            } else {
                error = "Installation completed but touchfs not found"
                installing = false
            }
        } catch {
            self.error = error.localizedDescription
            installing = false
        }
    }
}
