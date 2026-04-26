import SwiftUI

struct ChangePasswordSection: View {
    let cli: CLIService
    let store: FileStore
    let mount: MountService

    @State private var showForm = false
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var changing = false
    @State private var error: String?
    @State private var success = false

    var body: some View {
        Text("Change Password")
            .font(.headline)
        Text("Protected files are encrypted with the current password. Changing it will not re-encrypt them — unprotect them first or they will be inaccessible.")
            .font(.caption)
            .foregroundStyle(.secondary)

        if let error {
            Text(error)
                .foregroundStyle(.red)
                .font(.caption)
        }

        if success {
            Text("Password changed")
                .foregroundStyle(.green)
                .font(.caption)
        }

        if showForm {
            VStack(spacing: 8) {
                SecureField("New password", text: $newPassword)
                    .textFieldStyle(.roundedBorder)
                SecureField("Confirm", text: $confirmPassword)
                    .textFieldStyle(.roundedBorder)
            }
            .frame(maxWidth: 250)

            HStack {
                Button("Cancel") {
                    showForm = false
                    newPassword = ""
                    confirmPassword = ""
                    error = nil
                }
                Button(changing ? "Changing..." : "Change") {
                    Task { await changePassword() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(newPassword.isEmpty || changing)
            }
        } else {
            Button("Change Password...") { showForm = true }
        }
    }

    private func changePassword() async {
        error = nil
        success = false
        guard newPassword == confirmPassword else {
            error = "Passwords don't match"
            return
        }
        changing = true
        do {
            try await cli.reset()
        } catch {}
        do {
            try await cli.setPassword(newPassword)
            success = true
            showForm = false
            newPassword = ""
            confirmPassword = ""
        } catch {
            self.error = error.localizedDescription
        }
        changing = false
    }
}
