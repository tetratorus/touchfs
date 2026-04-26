import SwiftUI
import ServiceManagement

struct LoginItemToggle: View {
    @State private var enabled = SMAppService.mainApp.status == .enabled

    var body: some View {
        Toggle("Open at Login", isOn: $enabled)
            .onChange(of: enabled) { newValue in
                do {
                    if newValue {
                        try SMAppService.mainApp.register()
                    } else {
                        try SMAppService.mainApp.unregister()
                    }
                } catch {
                    print("Login item toggle failed: \(error)")
                    enabled = SMAppService.mainApp.status == .enabled
                }
            }
    }
}
