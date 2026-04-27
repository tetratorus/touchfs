import SwiftUI
import ServiceManagement

@main
struct TouchFSApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        Window("TouchFS", id: "main") {
            ContentView()
                .frame(minWidth: 500, minHeight: 400)
        }
        .commands {
            // Override Cmd+Q to just close the window, not quit.
            CommandGroup(replacing: .appTermination) {
                Button("Close Window") {
                    NSApplication.shared.keyWindow?.close()
                    NSApplication.shared.setActivationPolicy(.accessory)
                }
                .keyboardShortcut("q")
            }
        }

        MenuBarExtra("TouchFS", image: "MenuBarIcon") {
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
                (NSApplication.shared.delegate as? AppDelegate)?.quitForReal = true
                NSApplication.shared.terminate(nil)
            }
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        // If another instance is already running, activate it and exit immediately
        // before SwiftUI creates the MenuBarExtra.
        let bundleID = Bundle.main.bundleIdentifier ?? ""
        let running = NSWorkspace.shared.runningApplications.filter {
            $0.bundleIdentifier == bundleID && $0.processIdentifier != ProcessInfo.processInfo.processIdentifier
        }
        if let existing = running.first {
            existing.activate()
            exit(0)
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Dock Quit and Cmd+Q just close the window and hide dock icon.
        // Only "Quit TouchFS" from menu bar actually terminates.
        if !quitForReal {
            NSApplication.shared.keyWindow?.close()
            NSApplication.shared.setActivationPolicy(.accessory)
            return .terminateCancel
        }
        return .terminateNow
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    func applicationWillTerminate(_ notification: Notification) {
        MountService.shared.stop()
    }

    var quitForReal = false

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
