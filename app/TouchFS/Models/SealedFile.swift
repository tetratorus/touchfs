import Foundation

struct SealedFile: Identifiable, Codable, Equatable {
    var id: String { path }
    let path: String
    let addedAt: Date

    init(path: String) {
        self.path = path
        self.addedAt = Date()
    }

    var filename: String {
        URL(fileURLWithPath: path).lastPathComponent
    }

    var directory: String {
        URL(fileURLWithPath: path).deletingLastPathComponent().path
    }
}
