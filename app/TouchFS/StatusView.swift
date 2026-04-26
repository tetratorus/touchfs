import SwiftUI

enum AppScreen {
    case loading
    case install
    case onboarding
    case main
}

struct ContentView: View {
    @State private var screen: AppScreen = .loading
    let cli = CLIService()

    var body: some View {
        Group {
            switch screen {
            case .loading:
                ProgressView("Checking...")
            case .install:
                InstallView(screen: $screen, cli: cli)
            case .onboarding:
                OnboardingView(screen: $screen, cli: cli)
            case .main:
                MainView(cli: cli, screen: $screen)
            }
        }
        .task {
            if !cli.isInstalled {
                screen = .install
                return
            }
            // If there are files in the config, go straight to main view.
            // The mount will trigger Touch ID once — no need for a separate status check.
            let files = FileStore().load()
            if !files.isEmpty {
                screen = .main
                return
            }
            // No files — check if key exists to decide onboarding vs main.
            do {
                let status = try await cli.status()
                screen = status.hasKey ? .main : .onboarding
            } catch {
                screen = .onboarding
            }
        }
    }
}
