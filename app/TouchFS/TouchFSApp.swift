import SwiftUI
import ServiceManagement

@main
struct TouchFSApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        WindowGroup("TouchFS", id: "main") {
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
                    if window.title == "TouchFS" || window.contentViewController != nil {
                        window.makeKeyAndOrderFront(nil)
                        return
                    }
                }
                _ = (NSApplication.shared.delegate as? AppDelegate)?
                    .applicationShouldHandleReopen(NSApplication.shared, hasVisibleWindows: false)
            }
            .keyboardShortcut("o")

            Divider()

            LoginItemToggle()

            Divider()

            Button("Quit TouchFS") {
                AppDelegate.quitForReal = true
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

        // Start mount on launch, independent of window lifecycle.
        // Login items launch with the SwiftUI Window scene un-materialized
        // (Window + MenuBarExtra quirk on background launches), so MainView.onAppear
        // never fires and the mount would otherwise never start.
        startMountIfNeeded()
    }

    private func startMountIfNeeded() {
        let files = FileStore().load()
        guard !files.isEmpty else { return }
        let cli = CLIService()
        guard cli.isInstalled else { return }
        guard !MountService.shared.isRunning else { return }
        MountService.shared.start(
            binaryPath: cli.binaryPath,
            filePaths: files.map(\.path)
        )
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Dock Quit and Cmd+Q just close the window and hide dock icon.
        // Only "Quit TouchFS" from menu bar actually terminates.
        if !AppDelegate.quitForReal {
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

    static var quitForReal = false

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        NSApplication.shared.setActivationPolicy(.regular)
        NSApplication.shared.activate(ignoringOtherApps: true)

        for window in NSApplication.shared.windows {
            if window.title == "TouchFS" || window.contentViewController != nil {
                window.makeKeyAndOrderFront(nil)
                return true
            }
        }
        // No window exists — returning true lets AppKit run default reopen,
        // which causes WindowGroup to create a new window.
        return true
    }
}
