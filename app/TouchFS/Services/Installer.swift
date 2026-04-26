import Foundation

class Installer {
    static let downloadURL = "https://github.com/tetratorus/touchfs/releases/latest/download/touchfs.zip"
    static let installPath = "/Applications/touchfs.app"

    static func install(onProgress: @escaping (String) -> Void) async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Download.
        onProgress("Downloading touchfs...")
        let zipPath = tempDir.appendingPathComponent("touchfs.zip")
        let (data, response) = try await URLSession.shared.data(from: URL(string: downloadURL)!)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw InstallerError.downloadFailed
        }
        try data.write(to: zipPath)

        // Unzip.
        onProgress("Installing...")
        let unzip = Process()
        unzip.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        unzip.arguments = ["-x", "-k", zipPath.path, tempDir.path]
        try unzip.run()
        unzip.waitUntilExit()
        guard unzip.terminationStatus == 0 else {
            throw InstallerError.unzipFailed
        }

        // Move to /Applications (may need admin).
        let source = tempDir.appendingPathComponent("touchfs.app")
        guard FileManager.default.fileExists(atPath: source.path) else {
            throw InstallerError.unzipFailed
        }

        // Remove old version if exists.
        if FileManager.default.fileExists(atPath: installPath) {
            try FileManager.default.removeItem(atPath: installPath)
        }

        try FileManager.default.moveItem(atPath: source.path, toPath: installPath)

        onProgress("Done")
    }
}

enum InstallerError: LocalizedError {
    case downloadFailed
    case unzipFailed
    case installFailed

    var errorDescription: String? {
        switch self {
        case .downloadFailed: return "Failed to download touchfs"
        case .unzipFailed: return "Failed to extract touchfs"
        case .installFailed: return "Failed to install touchfs (admin permission needed)"
        }
    }
}
