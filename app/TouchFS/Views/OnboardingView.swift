import SwiftUI

struct OnboardingView: View {
    @Binding var screen: AppScreen
    let cli: CLIService

    @State private var step = 0
    @State private var password = ""
    @State private var confirm = ""
    @State private var error: String?
    @State private var saving = false

    var body: some View {
        VStack(spacing: 20) {
            if step == 0 {
                welcomeStep
            } else if step == 1 {
                passwordStep
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var welcomeStep: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 64))
                .foregroundStyle(.blue)

            Text("TouchFS")
                .font(.largeTitle.bold())

            Text("Protect your sensitive files with Touch ID encryption.\nAI editors, scripts, and apps can't read them without your fingerprint.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 400)

            Button("Continue") {
                Task {
                    // Check if key already exists — skip password if so.
                    if let status = try? await cli.status(), status.hasKey {
                        screen = .main
                    } else {
                        step = 1
                    }
                }
            }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .padding(.top, 10)

            Text("Touch ID may be required to check for an existing key")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
    }

    private var passwordStep: some View {
        VStack(spacing: 20) {
            Image(systemName: "key.fill")
                .font(.system(size: 48))
                .foregroundStyle(.orange)

            Text("Set a Password")
                .font(.title.bold())

            Text("This password derives an encryption key stored in your Mac's Keychain.\nAfter this, you'll only need Touch ID.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 400)

            VStack(spacing: 12) {
                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                SecureField("Confirm password", text: $confirm)
                    .textFieldStyle(.roundedBorder)
            }
            .frame(maxWidth: 300)

            if let error {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.callout)
            }

            Button(saving ? "Saving..." : "Continue") {
                Task { await savePassword() }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(password.isEmpty || saving)
            .keyboardShortcut(.defaultAction)
        }
    }

    private func savePassword() async {
        error = nil
        guard password == confirm else {
            error = "Passwords don't match"
            return
        }
        saving = true
        do {
            try await cli.setPassword(password)
            screen = .main
        } catch {
            self.error = error.localizedDescription
        }
        saving = false
    }
}
