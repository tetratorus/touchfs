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
            do {
                let status = try await cli.status()
                screen = status.hasKey ? .main : .onboarding
            } catch {
                screen = .onboarding
            }
        }
    }
}
