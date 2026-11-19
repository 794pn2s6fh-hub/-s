import SwiftUI
import CoreTransferable
import UniformTypeIdentifiers

private struct SectionZIPExport: Transferable, Identifiable {
    let id = UUID()
    let fileURL: URL

    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .zip) { export in
            SentTransferredFile(export.fileURL)
        }
    }
}

struct ScannerView: View {
    @StateObject private var engine = ScanEngine()

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 7) {
                        if engine.logs.isEmpty {
                            Text("Waiting for scan")
                                .foregroundStyle(.secondary)
                        } else {
                            ScrollView {
                                LazyVStack(alignment: .leading, spacing: 3) {
                                    ForEach(Array(engine.logs.enumerated()), id: \.offset) { _, line in
                                        Text(line)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                    }
                                }
                            }
                            .frame(height: 145)
                        }
                    }
                    .font(.system(size: 10, design: .monospaced))
                    .platformTextSelection()

                } header: {
                    Text("Logs")
                }

                Section {
                    ForEach(engine.results.filter { !$0.root.usesDirectAccess }) { result in
                        ContainerCategoryRow(
                            engine: engine,
                            result: result,
                            symbol: categorySymbol(for: result.root.id),
                            count: categoryCount(result)
                        )
                    }
                } header: {
                    Text("Containers")
                }

                Section {
                    ForEach(engine.results.filter { $0.root.usesDirectAccess }) { result in
                        ContainerCategoryRow(
                            engine: engine,
                            result: result,
                            symbol: categorySymbol(for: result.root.id),
                            count: categoryCount(result)
                        )
                    }
                } header: {
                    Text("Direct Paths")
                }
            }
            #if os(iOS)
            .listStyle(.insetGrouped)
            #else
            .listStyle(.automatic)
            #endif
            .navigationTitle("worsewatched")
            .task {
                engine.scanOnLaunch()
            }
        }
    }

    private func categorySymbol(for id: String) -> String {
        switch id {
        case "applications": return "app"
        case "plugins": return "puzzlepiece.extension"
        case "app-groups": return "person.3"
        case "daemons": return "gearshape.2"
        case "system": return "gearshape"
        case "system-groups": return "square.stack.3d.up"
        case "direct-system-library": return "books.vertical"
        case "direct-system-cryptexes": return "shippingbox"
        case "direct-system-developer": return "hammer"
        case "direct-applications": return "app"
        case "direct-usr-lib": return "folder"
        case "direct-usr-bin": return "terminal"
        default: return "folder"
        }
    }

    private func categoryCount(_ result: ContainerScanResult) -> String {
        if engine.isScanning && result.status == "Scanning…" { return "…" }
        if result.root.usesDirectAccess {
            let failed = result.status.contains("failed")
                || result.status.contains("Could not")
                || result.status.contains("not a directory")
            return failed ? "!" : String(result.entries.count)
        }
        return result.entries.isEmpty ? "—" : String(result.entries.count)
    }
}

private struct ContainerCategoryRow: View {
    @ObservedObject var engine: ScanEngine
    let result: ContainerScanResult
    let symbol: String
    let count: String

    @State private var isExporting = false
    @State private var isShowingCategory = false
    @State private var exportedZIP: SectionZIPExport?
    @State private var exportError: String?
    @State private var showingExportError = false

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: symbol)
                .foregroundStyle(.secondary)
                .frame(width: 22)
            Text(result.root.title)
            Spacer()
            if isExporting {
                ProgressView()
            } else {
                Text(count)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            guard !isExporting else { return }
            isShowingCategory = true
        }
        // Do not use contextMenu here: watchOS 26 does not reliably expose it
        // for this row. A native long-press starts ZIP creation immediately.
        .highPriorityGesture(
            LongPressGesture(minimumDuration: 0.5, maximumDistance: 35)
                .onEnded { _ in exportSection() }
        )
        .navigationDestination(isPresented: $isShowingCategory) {
            if result.root.usesDirectAccess {
                ContainerDirectoryView(
                    path: result.root.path,
                    title: result.root.title,
                    usesDirectAccess: true
                )
            } else {
                ContainerCategoryView(engine: engine, root: result.root)
            }
        }
        .sheet(item: $exportedZIP) { archive in
            VStack(spacing: 14) {
                Text(result.root.title)
                    .font(.headline)
                Text(archive.fileURL.lastPathComponent)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .multilineTextAlignment(.center)
                ShareLink(
                    item: archive,
                    preview: SharePreview(archive.fileURL.lastPathComponent)
                ) {
                    Label("Share ZIP", systemImage: "square.and.arrow.up")
                }
            }
            .padding()
        }
        .alert("Export Failed", isPresented: $showingExportError) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(exportError ?? "The section could not be exported.")
        }
    }

    @MainActor
    private func exportSection() {
        guard !result.root.usesDirectAccess, !isExporting, !result.entries.isEmpty else { return }
        isExporting = true
        Task {
            do {
                let url = try await engine.createArchive(for: result.root)
                exportedZIP = SectionZIPExport(fileURL: url)
            } catch {
                exportError = error.localizedDescription
                showingExportError = true
            }
            isExporting = false
        }
    }
}

private struct ContainerCategoryView: View {
    @ObservedObject var engine: ScanEngine
    let root: ContainerRoot

    private var result: ContainerScanResult {
        engine.results.first(where: { $0.root.id == root.id }) ?? ContainerScanResult(root: root)
    }

    var body: some View {
        List {
            if result.entries.isEmpty {
                Text(result.status)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(result.entries) { entry in
                    NavigationLink {
                        ContainerDirectoryView(
                            path: entry.path,
                            title: entry.displayName,
                            usesDirectAccess: root.usesDirectAccess
                        )
                    } label: {
                        ContainerEntryRow(entry: entry)
                    }
                }
            }
        }
        #if os(iOS)
        .listStyle(.insetGrouped)
        #else
        .listStyle(.automatic)
        #endif
        .navigationTitle(result.root.title)
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}

private struct ContainerEntryRow: View {
    let entry: ContainerEntry

    @State private var directorySize: Int64?
    @State private var didFinishSizeLookup = false
    @State private var isLoadingSize = true

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: "folder")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.displayName)
                    .font(.system(size: 12, design: .monospaced))
                    .lineLimit(2)
                Text(formattedSize)
                    .font(.system(size: 9))
                    .foregroundStyle(.secondary)
                Text(formattedCreationDate)
                    .font(.system(size: 9))
                    .foregroundStyle(.secondary)
            }
        }
        .task {
            await loadDirectorySize()
        }
    }

    private var formattedSize: String {
        if let directorySize {
            return ByteCountFormatter.string(fromByteCount: directorySize, countStyle: .file)
        }
        if didFinishSizeLookup { return "Unavailable" }
        return isLoadingSize ? "Calculating…" : "—"
    }

    private var formattedCreationDate: String {
        guard let date = entry.creationDate else { return "Unavailable" }
        return date.formatted(date: .numeric, time: .shortened)
    }

    @MainActor
    private func loadDirectorySize() async {
        guard !didFinishSizeLookup else { return }
        guard let appGroupIdentifier = WorseQuery.getAppGroupIdentifier() else {
            didFinishSizeLookup = true
            isLoadingSize = false
            return
        }

        let requestedPath = entry.path
        let size = await Task.detached(priority: .utility) {
            ContainerFileAccess.directoryContentSize(
                at: requestedPath,
                appGroupIdentifier: appGroupIdentifier
            )
        }.value

        guard !Task.isCancelled else {
            isLoadingSize = false
            return
        }
        directorySize = size
        didFinishSizeLookup = true
        isLoadingSize = false
    }
}

private struct ContainerDirectoryView: View {
    let path: String
    let title: String
    let usesDirectAccess: Bool

    @State private var files: [BrowserFile] = []
    @State private var isLoading = true
    @State private var errorMessage: String?
    @State private var accessHandle: Int64?
    @State private var didLoad = false

    var body: some View {
        List {
            if isLoading {
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Opening directory…")
                        .foregroundStyle(.secondary)
                }
            } else if let errorMessage {
                Text(errorMessage)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else if files.isEmpty {
                Text("This directory is empty")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(files) { file in
                    if file.isDirectory {
                        NavigationLink {
                            ContainerDirectoryView(
                                path: file.path,
                                title: file.name,
                                usesDirectAccess: usesDirectAccess
                            )
                        } label: {
                            fileRow(file, symbol: "folder")
                        }
                    } else {
                        NavigationLink {
                            ContainerFilePreviewView(
                                path: file.path,
                                parentPath: path,
                                title: file.name,
                                usesDirectAccess: usesDirectAccess
                            )
                        } label: {
                            fileRow(file, symbol: "doc")
                        }
                    }
                }
            }
        }
        #if os(iOS)
        .listStyle(.insetGrouped)
        #else
        .listStyle(.automatic)
        #endif
        .navigationTitle(title)
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .task {
            await loadDirectory()
        }
        .onDisappear { releaseDirectoryGrant() }
    }

    private func fileRow(_ file: BrowserFile, symbol: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(file.isHidden ? .secondary : .primary)
            VStack(alignment: .leading, spacing: 2) {
                Text(file.name)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .foregroundStyle(file.isHidden ? .secondary : .primary)
                if let modifiedAt = file.modifiedAt {
                    Text(modifiedAt.formatted(date: .abbreviated, time: .shortened))
                        .font(.system(size: 9))
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 4)
            if !file.isDirectory {
                Text(ByteCountFormatter.string(fromByteCount: file.byteCount, countStyle: .file))
                    .font(.system(size: 9))
                    .foregroundStyle(.secondary)
            }
        }
    }

    @MainActor
    private func loadDirectory() async {
        guard !didLoad else { return }
        didLoad = true
        isLoading = true

        let requestedPath = path
        let result: DirectoryLoadResult
        if usesDirectAccess {
            result = await Task.detached(priority: .userInitiated) {
                ContainerFileAccess.listDirectoryDirect(at: requestedPath)
            }.value
        } else {
            guard let appGroupIdentifier = WorseQuery.getAppGroupIdentifier() else {
                errorMessage = "No sideloader App Group entitlement is available."
                isLoading = false
                return
            }
            result = await Task.detached(priority: .userInitiated) {
                ContainerFileAccess.listDirectory(at: requestedPath, appGroupIdentifier: appGroupIdentifier)
            }.value
        }

        guard !Task.isCancelled else {
            if let handle = result.handle { WorseQuery.release(handle) }
            didLoad = false
            isLoading = false
            return
        }

        accessHandle = result.handle
        files = result.entries
        errorMessage = result.error
        isLoading = false
    }

    private func releaseDirectoryGrant() {
        guard let handle = accessHandle else { return }
        WorseQuery.release(handle)
        accessHandle = nil
    }
}

private struct ContainerFilePreviewView: View {
    let path: String
    let parentPath: String
    let title: String
    let usesDirectAccess: Bool

    @State private var previewText = "Loading file…"
    @State private var byteCount: Int64 = 0
    @State private var isLoading = true

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text(title)
                    .font(.headline)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text(ByteCountFormatter.string(fromByteCount: byteCount, countStyle: .file))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Divider()
                Text(previewText)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .platformTextSelection()
            }
            .padding()
        }
        .navigationTitle(title)
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .overlay {
            if isLoading { ProgressView() }
        }
        .task { await loadFile() }
    }

    @MainActor
    private func loadFile() async {
        let requestedPath = path
        let result: FileReadResult
        if usesDirectAccess {
            result = await Task.detached(priority: .userInitiated) {
                ContainerFileAccess.readFileDirect(at: requestedPath)
            }.value
        } else {
            guard let appGroupIdentifier = WorseQuery.getAppGroupIdentifier() else {
                previewText = "No sideloader App Group entitlement is available."
                isLoading = false
                return
            }
            let requestedParent = parentPath
            result = await Task.detached(priority: .userInitiated) {
                ContainerFileAccess.readFile(
                    at: requestedPath,
                    parentPath: requestedParent,
                    appGroupIdentifier: appGroupIdentifier
                )
            }.value
        }

        guard !Task.isCancelled else { return }
        byteCount = result.byteCount
        if let error = result.error {
            previewText = error
        } else if let data = result.data {
            previewText = Self.render(data: data, path: path)
        } else {
            previewText = "The file could not be read."
        }
        isLoading = false
    }

    private static func render(data: Data, path: String) -> String {
        let ext = URL(fileURLWithPath: path).pathExtension.lowercased()
        if ext == "plist",
           let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
           let xml = try? PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0),
           let text = String(data: xml, encoding: .utf8) {
            return text
        }

        if let text = String(data: data, encoding: .utf8) {
            return text.isEmpty ? "(empty file)" : text
        }

        let prefix = data.prefix(512)
        let hex = prefix.enumerated().map { index, byte in
            let separator = index.isMultiple(of: 16) ? "\n" : " "
            return separator + String(format: "%02X", byte)
        }.joined()
        let suffix = data.count > prefix.count ? "\n… preview truncated …" : ""
        return "Binary file — first \(prefix.count) of \(data.count) bytes:\n\(hex)\(suffix)"
    }
}

private extension View {
    @ViewBuilder
    func platformTextSelection() -> some View {
        #if os(iOS)
        self.textSelection(.enabled)
        #else
        self
        #endif
    }
}
