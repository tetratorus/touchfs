import Foundation

class Installer {
    static let touchfsURL = "https://github.com/tetratorus/touchfs/releases/latest/download/touchfs.zip"
    static let fusetURL = "https://github.com/macos-fuse-t/fuse-t/releases/download/1.2.1/fuse-t-macos-installer-1.2.1.pkg"

    static func install(onProgress: @escaping (String) -> Void) async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let cli = CLIService()

        // Install fuse-t if not present.
        if !cli.hasFuseT {
            onProgress("Downloading fuse-t...")
            let pkgPath = tempDir.appendingPathComponent("fuse-t.pkg")
            let (pkgData, pkgResponse) = try await URLSession.shared.data(from: URL(string: fusetURL)!)
            guard let pkgHttp = pkgResponse as? HTTPURLResponse, pkgHttp.statusCode == 200 else {
                throw InstallerError.downloadFailed
            }
            try pkgData.write(to: pkgPath)

            onProgress("Installing fuse-t (admin password required)...")
            let open = Process()
            open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
            open.arguments = ["-W", pkgPath.path]
            try open.run()
            open.waitUntilExit()
            guard FileManager.default.fileExists(atPath: "/usr/local/lib/libfuse-t.dylib") else {
                throw InstallerError.fusetInstallFailed
            }
        }

        // Download touchfs if not present.
        if cli.hasBinary {
            onProgress("Done")
            return
        }
        onProgress("Downloading touchfs...")
        let zipPath = tempDir.appendingPathComponent("touchfs.zip")
        let (data, response) = try await URLSession.shared.data(from: URL(string: touchfsURL)!)
        if let http = response as? HTTPURLResponse {
            print("Download status: \(http.statusCode), size: \(data.count)")
            guard http.statusCode == 200 else {
                throw InstallerError.downloadFailed
            }
        } else {
            print("Download response is not HTTP: \(response)")
            throw InstallerError.downloadFailed
        }
        try data.write(to: zipPath)

        // Unzip and extract the binary.
        onProgress("Installing touchfs...")
        let unzip = Process()
        unzip.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        unzip.arguments = ["-x", "-k", zipPath.path, tempDir.path]
        try unzip.run()
        unzip.waitUntilExit()
        guard unzip.terminationStatus == 0 else {
            throw InstallerError.unzipFailed
        }

        let sourceBinary = tempDir.appendingPathComponent("touchfs.app/Contents/MacOS/touchfs")
        guard FileManager.default.fileExists(atPath: sourceBinary.path) else {
            throw InstallerError.unzipFailed
        }

        // Install binary to ~/Library/Application Support/touchfs/
        let installDir = URL(fileURLWithPath: CLIService.installedDir)
        try FileManager.default.createDirectory(at: installDir, withIntermediateDirectories: true)

        let dest = URL(fileURLWithPath: CLIService.installedPath)
        if FileManager.default.fileExists(atPath: dest.path) {
            try FileManager.default.removeItem(at: dest)
        }
        try FileManager.default.copyItem(at: sourceBinary, to: dest)

        onProgress("Done")
    }
}

enum InstallerError: LocalizedError {
    case downloadFailed
    case unzipFailed
    case installFailed
    case fusetInstallFailed

    var errorDescription: String? {
        switch self {
        case .downloadFailed: return "Failed to download"
        case .unzipFailed: return "Failed to extract"
        case .installFailed: return "Failed to install"
        case .fusetInstallFailed: return "Failed to install fuse-t (admin password may be needed)"
        }
    }
}
