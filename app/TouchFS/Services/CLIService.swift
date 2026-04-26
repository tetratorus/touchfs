import Foundation

struct CLIStatus: Codable {
    let hasKey: Bool
    let version: String

    enum CodingKeys: String, CodingKey {
        case hasKey = "has_key"
        case version
    }
}

class CLIService {
    static let installedPath = "/Applications/touchfs-cli.app/Contents/MacOS/touchfs"

    var isInstalled: Bool {
        hasBinary && hasFuseT
    }

    var hasBinary: Bool {
        // Check file exists and isn't a broken symlink.
        var s = stat()
        return stat(Self.installedPath, &s) == 0
    }

    func checkBinaryWorks() async -> Bool {
        do {
            let v = try await version()
            return !v.isEmpty
        } catch {
            return false
        }
    }

    var hasFuseT: Bool {
        FileManager.default.fileExists(atPath: "/usr/local/lib/libfuse-t.dylib")
        && FileManager.default.isExecutableFile(atPath: "/usr/local/bin/go-nfsv4")
    }


    var binaryPath: String {
        if FileManager.default.isExecutableFile(atPath: Self.installedPath) {
            return Self.installedPath
        }
        // Fallback to PATH.
        for path in ["/usr/local/bin/touchfs", "/opt/homebrew/bin/touchfs"] {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        return "touchfs"
    }

    func version() async throws -> String {
        try await run(args: ["version"]).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func status() async throws -> CLIStatus {
        let output = try await run(args: ["status"])
        let data = Data(output.utf8)
        return try JSONDecoder().decode(CLIStatus.self, from: data)
    }

    func setPassword(_ password: String) async throws {
        try await run(args: ["set", "--stdin"], stdin: "\(password)\n\(password)\n")
    }

    func seal(path: String) async throws {
        try await run(args: ["seal", path])
    }

    func unseal(path: String) async throws {
        try await run(args: ["unseal", path])
    }

    func reset() async throws {
        try await run(args: ["reset"])
    }

    /// Checks if a file is sealed. Recovers broken symlinks from crashed mounts first.
    func isSealedFile(path: String) -> Bool {
        var s = stat()
        if lstat(path, &s) == 0 && (s.st_mode & S_IFLNK) == S_IFLNK {
            if let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: path),
               dest.contains("/touchfs/") {
                // Check if target exists (mounted) or broken (crashed).
                if access(dest, F_OK) != 0 {
                    // Broken symlink — recover via touchfs recover.
                    let proc = Process()
                    proc.executableURL = URL(fileURLWithPath: binaryPath)
                    proc.arguments = ["recover", path]
                    proc.standardOutput = FileHandle.nullDevice
                    proc.standardError = FileHandle.nullDevice
                    try? proc.run()
                    proc.waitUntilExit()
                    // After recovery, check if it's now a regular sealed file.
                    return isSealedHeader(path: path)
                }
                return true // Mounted symlink = sealed.
            }
            return false // Non-touchfs symlink.
        }
        return isSealedHeader(path: path)
    }

    private func isSealedHeader(path: String) -> Bool {
        guard let handle = FileHandle(forReadingAtPath: path) else { return false }
        defer { handle.closeFile() }
        let data = handle.readData(ofLength: 9)
        return String(data: data, encoding: .utf8) == "#touchfs\n"
    }

    @discardableResult
    private func run(args: [String], stdin: String? = nil) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: binaryPath)
            process.arguments = args

            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()
            process.standardOutput = stdoutPipe
            process.standardError = stderrPipe

            if let input = stdin {
                let stdinPipe = Pipe()
                process.standardInput = stdinPipe
                stdinPipe.fileHandleForWriting.write(Data(input.utf8))
                stdinPipe.fileHandleForWriting.closeFile()
            }

            process.terminationHandler = { _ in
                let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8) ?? ""

                if process.terminationStatus != 0 {
                    let errData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
                    let errMsg = String(data: errData, encoding: .utf8) ?? "unknown error"
                    continuation.resume(throwing: CLIError.failed(code: Int(process.terminationStatus), message: errMsg))
                } else {
                    continuation.resume(returning: output)
                }
            }

            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}

enum CLIError: LocalizedError {
    case failed(code: Int, message: String)

    var errorDescription: String? {
        switch self {
        case .failed(_, let message):
            return message.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }
}
