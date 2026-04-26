import Foundation

class Installer {
    static let touchfsURL = "https://github.com/tetratorus/touchfs/releases/latest/download/touchfs.zip"
    static let fusetURL = "https://github.com/macos-fuse-t/fuse-t/releases/download/1.2.1/fuse-t-macos-installer-1.2.1.pkg"
    static let installPath = "/Applications/touchfs.app"

    static var isFuseTInstalled: Bool {
        FileManager.default.fileExists(atPath: "/usr/local/lib/libfuse-t.dylib")
    }

    static func install(onProgress: @escaping (String) -> Void) async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Install fuse-t if not present.
        if !isFuseTInstalled {
            onProgress("Downloading fuse-t...")
            let pkgPath = tempDir.appendingPathComponent("fuse-t.pkg")
            let (pkgData, pkgResponse) = try await URLSession.shared.data(from: URL(string: fusetURL)!)
            guard let pkgHttp = pkgResponse as? HTTPURLResponse, pkgHttp.statusCode == 200 else {
                throw InstallerError.downloadFailed
            }
            try pkgData.write(to: pkgPath)

            onProgress("Installing fuse-t...")
            let installer = Process()
            installer.executableURL = URL(fileURLWithPath: "/usr/sbin/installer")
            installer.arguments = ["-pkg", pkgPath.path, "-target", "/"]
            try installer.run()
            installer.waitUntilExit()
            guard installer.terminationStatus == 0 else {
                throw InstallerError.fusetInstallFailed
            }
        }

        // Download touchfs.
        onProgress("Downloading touchfs...")
        let zipPath = tempDir.appendingPathComponent("touchfs.zip")
        let (data, response) = try await URLSession.shared.data(from: URL(string: touchfsURL)!)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw InstallerError.downloadFailed
        }
        try data.write(to: zipPath)

        // Unzip.
        onProgress("Installing touchfs...")
        let unzip = Process()
        unzip.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        unzip.arguments = ["-x", "-k", zipPath.path, tempDir.path]
        try unzip.run()
        unzip.waitUntilExit()
        guard unzip.terminationStatus == 0 else {
            throw InstallerError.unzipFailed
        }

        let source = tempDir.appendingPathComponent("touchfs.app")
        guard FileManager.default.fileExists(atPath: source.path) else {
            throw InstallerError.unzipFailed
        }

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
    case fusetInstallFailed

    var errorDescription: String? {
        switch self {
        case .downloadFailed: return "Failed to download"
        case .unzipFailed: return "Failed to extract"
        case .installFailed: return "Failed to install"
        case .fusetInstallFailed: return "Failed to install fuse-t (admin permission may be needed)"
        }
    }
}
