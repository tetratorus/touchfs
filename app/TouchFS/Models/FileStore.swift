import Foundation

class FileStore {
    private let configURL: URL = {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".config/touchfs/files.json")
    }()

    func load() -> [SealedFile] {
        guard let data = try? Data(contentsOf: configURL) else { return [] }
        return (try? JSONDecoder().decode([SealedFile].self, from: data)) ?? []
    }

    func save(_ files: [SealedFile]) {
        let dir = configURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(files) {
            try? data.write(to: configURL)
        }
    }
}
