import SwiftUI

struct CLIInstallSection: View {
    @State private var installed = FileManager.default.fileExists(atPath: "/usr/local/bin/touchfs")
    @State private var error: String?

    private let cli = CLIService()

    var body: some View {
        Text("CLI Tool")
            .font(.headline)
        Text("Make touchfs available in the terminal.")
            .font(.caption)
            .foregroundStyle(.secondary)

        if let error {
            Text(error)
                .foregroundStyle(.red)
                .font(.caption)
        }

        if installed {
            HStack(spacing: 8) {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.caption)
                Text("/usr/local/bin/touchfs")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Uninstall") { uninstallCLI() }
                    .foregroundStyle(.red)
            }
        } else {
            Button("Install CLI") { installCLI() }
        }
    }

    private func installCLI() {
        error = nil
        let source = cli.binaryPath
        let dest = "/usr/local/bin/touchfs"

        do {
            try FileManager.default.createDirectory(atPath: "/usr/local/bin", withIntermediateDirectories: true)
            try? FileManager.default.removeItem(atPath: dest)
            try FileManager.default.createSymbolicLink(atPath: dest, withDestinationPath: source)
            installed = true
        } catch {
            self.error = "Failed: \(error.localizedDescription)"
        }
    }

    private func uninstallCLI() {
        error = nil
        do {
            try FileManager.default.removeItem(atPath: "/usr/local/bin/touchfs")
            installed = false
        } catch {
            self.error = "Failed: \(error.localizedDescription)"
        }
    }
}
