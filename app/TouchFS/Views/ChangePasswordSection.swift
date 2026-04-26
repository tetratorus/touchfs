import SwiftUI

struct ChangePasswordSection: View {
    let cli: CLIService
    let store: FileStore
    let mount: MountService

    @State private var showSheet = false

    var body: some View {
        Text("Change Password")
            .font(.headline)
        Button("Change Password...") { showSheet = true }
            .sheet(isPresented: $showSheet) {
                ChangePasswordSheet(cli: cli)
            }
    }
}

struct ChangePasswordSheet: View {
    let cli: CLIService
    @Environment(\.dismiss) var dismiss

    @State private var confirmed = false
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var changing = false
    @State private var error: String?

    var body: some View {
        VStack(spacing: 16) {
            if !confirmed {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 40))
                    .foregroundStyle(.orange)
                Text("Change Password")
                    .font(.title2.bold())
                Text("Protected files are encrypted with your current password. Changing it will not re-encrypt them — unprotect them first or they will be inaccessible.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 350)
                HStack {
                    Button("Cancel") { dismiss() }
                    Button("I understand, continue") { confirmed = true }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                Text("New Password")
                    .font(.title2.bold())
                VStack(spacing: 8) {
                    SecureField("New password", text: $newPassword)
                        .textFieldStyle(.roundedBorder)
                    SecureField("Confirm", text: $confirmPassword)
                        .textFieldStyle(.roundedBorder)
                }
                .frame(maxWidth: 250)

                if let error {
                    Text(error)
                        .foregroundStyle(.red)
                        .font(.callout)
                }

                HStack {
                    Button("Cancel") { dismiss() }
                    Button(changing ? "Changing..." : "Change") {
                        Task { await changePassword() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(newPassword.isEmpty || changing)
                }
            }
        }
        .padding(30)
        .frame(width: 400)
    }

    private func changePassword() async {
        error = nil
        guard newPassword == confirmPassword else {
            error = "Passwords don't match"
            return
        }
        changing = true
        do { try await cli.reset() } catch {}
        do {
            try await cli.setPassword(newPassword)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
        changing = false
    }
}
