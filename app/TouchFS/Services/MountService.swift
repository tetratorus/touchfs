import Foundation

class MountService {
    static let shared = MountService()
    private var process: Process?
    private var stderrTask: Task<Void, Never>?

    var isRunning: Bool { process?.isRunning ?? false }

    func start(binaryPath: String, filePaths: [String], onLogLine: ((String) -> Void)? = nil) {
        guard !filePaths.isEmpty else { return }
        stop()
        // Kill any orphaned mount processes from previous app runs.
        killOrphans()

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: binaryPath)
        proc.arguments = ["mount"] + filePaths

        let stderrPipe = Pipe()
        proc.standardError = stderrPipe
        proc.standardOutput = FileHandle.nullDevice

        proc.terminationHandler = { p in
            print("Mount exited with status \(p.terminationStatus)")
        }

        do {
            try proc.run()
            process = proc
            print("Mount started with \(filePaths.count) files")
        } catch {
            print("Failed to start mount: \(error)")
            return
        }

        // Read stderr for log lines.
        if let onLogLine {
            stderrTask = Task.detached { [weak self] in
                let handle = stderrPipe.fileHandleForReading
                while self?.process?.isRunning == true {
                    let data = handle.availableData
                    if data.isEmpty { break }
                    if let str = String(data: data, encoding: .utf8) {
                        for line in str.split(separator: "\n") {
                            onLogLine(String(line))
                        }
                    }
                }
            }
        }
    }

    func stop() {
        stderrTask?.cancel()
        stderrTask = nil

        guard let proc = process, proc.isRunning else {
            process = nil
            return
        }

        proc.interrupt() // SIGINT — triggers clean shutdown in Go.

        // Wait up to 5 seconds for cleanup.
        let deadline = Date().addingTimeInterval(5)
        while proc.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.1)
        }

        if proc.isRunning {
            proc.terminate()
        }
        process = nil
        print("Mount stopped")
    }

    private func killOrphans() {
        // Find and kill any existing touchfs mount processes not owned by us.
        let find = Process()
        find.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        find.arguments = ["-INT", "-f", "touchfs.*mount"]
        find.standardOutput = FileHandle.nullDevice
        find.standardError = FileHandle.nullDevice
        try? find.run()
        find.waitUntilExit()
        // Brief wait for cleanup.
        Thread.sleep(forTimeInterval: 1.0)
    }
}
