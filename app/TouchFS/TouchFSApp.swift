import SwiftUI
import ServiceManagement

@main
struct TouchFSApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        Window("TouchFS", id: "main") {
            ContentView()
                .frame(minWidth: 500, minHeight: 400)
                .onAppear {
                    // During onboarding, show dock icon so user sees the app.
                    NSApplication.shared.setActivationPolicy(.regular)
                }
        }
        .commands {
            // Override Cmd+Q to just close the window, not quit.
            CommandGroup(replacing: .appTermination) {
                Button("Close Window") {
                    NSApplication.shared.keyWindow?.close()
                }
                .keyboardShortcut("q")
            }
        }

        MenuBarExtra("TouchFS", systemImage: "lock.shield") {
            let count = FileStore().load().count
            Text("Protecting \(count) file\(count == 1 ? "" : "s")")

            Divider()

            Button("Open TouchFS") {
                NSApplication.shared.setActivationPolicy(.regular)
                NSApplication.shared.activate(ignoringOtherApps: true)
                for window in NSApplication.shared.windows {
                    if window.title == "TouchFS" {
                        window.makeKeyAndOrderFront(nil)
                        return
                    }
                }
            }
            .keyboardShortcut("o")

            Divider()

            LoginItemToggle()

            Divider()

            Button("Quit TouchFS") {
                NSApplication.shared.terminate(nil)
            }
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // If another instance is already running, activate it and quit this one.
        let bundleID = Bundle.main.bundleIdentifier ?? ""
        let running = NSWorkspace.shared.runningApplications.filter {
            $0.bundleIdentifier == bundleID && $0.processIdentifier != ProcessInfo.processInfo.processIdentifier
        }
        if let existing = running.first {
            existing.activate()
            NSApplication.shared.terminate(nil)
            return
        }

        NSApplication.shared.setActivationPolicy(.accessory)
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Stop mount on quit — restores sealed files.
        MountService.shared.stop()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            for window in NSApplication.shared.windows {
                if window.title == "TouchFS" {
                    window.makeKeyAndOrderFront(nil)
                    break
                }
            }
        }
        return false
    }
}
