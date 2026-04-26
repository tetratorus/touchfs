import SwiftUI

struct ContentView: View {
    let cli = CLIService()

    var body: some View {
        MainView(cli: cli)
            .frame(minWidth: 500, minHeight: 400)
    }
}
