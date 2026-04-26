import AppKit

struct FilePicker {
    static func pickFiles(title: String = "Select files", multiselect: Bool = true) -> [URL] {
        let panel = NSOpenPanel()
        panel.title = title
        panel.allowsMultipleSelection = multiselect
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.showsHiddenFiles = true

        guard panel.runModal() == .OK else { return [] }
        return panel.urls
    }
}
