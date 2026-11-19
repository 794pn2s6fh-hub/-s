import Foundation
import Combine
import Darwin

struct ContainerRoot: Identifiable, Hashable {
    let id: String
    let title: String
    let path: String
    let usesDirectAccess: Bool

    init(id: String, title: String, path: String, usesDirectAccess: Bool = false) {
        self.id = id
        self.title = title
        self.path = path
        self.usesDirectAccess = usesDirectAccess
    }

    /// pathleak normalizes /private/var paths to /var paths internally.
    var enumerationPath: String {
        path.hasPrefix("/private/var/") ? String(path.dropFirst("/private".count)) : path
    }

    /// These are the container roots discovered through pathleak + Worse Query.
    static let all: [ContainerRoot] = [
        ContainerRoot(
            id: "applications",
            title: "Apps",
            path: "/var/mobile/Containers/Data/Application"
        ),
        ContainerRoot(
            id: "plugins",
            title: "Plugins",
            path: "/var/mobile/Containers/Data/PluginKitPlugin"
        ),
        ContainerRoot(
            id: "app-groups",
            title: "Groups",
            path: "/private/var/mobile/Containers/Shared/AppGroup"
        ),
        ContainerRoot(
            id: "daemons",
            title: "Daemons",
            path: "/var/mobile/Containers/Data/InternalDaemon"
        ),
        ContainerRoot(
            id: "system",
            title: "System",
            path: "/private/var/containers/Data/System"
        ),
        ContainerRoot(
            id: "system-groups",
            title: "SystemGroups",
            path: "/var/containers/Shared/SystemGroup"
        )
    ]

    /// Experimental paths are opened directly, without pathleak or Worse Query.
    static let directPaths: [ContainerRoot] = [
        ContainerRoot(
            id: "direct-system-library",
            title: "/System/Library",
            path: "/System/Library",
            usesDirectAccess: true
        ),
        ContainerRoot(
            id: "direct-system-cryptexes",
            title: "/System/Cryptexes",
            path: "/System/Cryptexes",
            usesDirectAccess: true
        ),
        ContainerRoot(
            id: "direct-system-developer",
            title: "/System/Developer",
            path: "/System/Developer",
            usesDirectAccess: true
        ),
        ContainerRoot(
            id: "direct-applications",
            title: "/Applications",
            path: "/Applications",
            usesDirectAccess: true
        ),
        ContainerRoot(
            id: "direct-usr-lib",
            title: "/usr/lib",
            path: "/usr/lib",
            usesDirectAccess: true
        ),
        ContainerRoot(
            id: "direct-usr-bin",
            title: "/usr/bin",
            path: "/usr/bin",
            usesDirectAccess: true
        )
    ]

    /// System container roots are only probed on watchOS 27 and later.
    /// Direct paths are shown on both platforms and are probed without Worse Query.
    static var supported: [ContainerRoot] {
        var roots = all + directPaths
        #if os(watchOS)
        let watchMajorVersion = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        if watchMajorVersion < 27 {
            roots.removeAll { $0.id == "system" || $0.id == "system-groups" }
        }
        #endif
        return roots
    }
}

struct ContainerEntry: Identifiable, Hashable {
    let path: String
    let displayName: String
    let creationDate: Date?

    var id: String { path }
}

struct ContainerScanResult: Identifiable {
    let root: ContainerRoot
    var entries: [ContainerEntry] = []
    var status: String = "Waiting to scan"

    var id: String { root.id }
}


/// One immediate child in a browsed container directory.
struct BrowserFile: Identifiable, Hashable {
    let path: String
    let name: String
    let isDirectory: Bool
    let isHidden: Bool
    let byteCount: Int64
    let modifiedAt: Date?

    var id: String { path }
}

struct DirectoryLoadResult {
    let handle: Int64?
    let entries: [BrowserFile]
    let error: String?
}

struct FileReadResult {
    let data: Data?
    let byteCount: Int64
    let error: String?
}

/// Provides Worse Query-backed container access and separate direct filesystem
/// access for the experimental system paths. The caller owns any returned grant.
enum ContainerFileAccess {
    private static let operationLock = NSRecursiveLock()

    static func listDirectory(at path: String, appGroupIdentifier: String) -> DirectoryLoadResult {
        operationLock.lock()
        defer { operationLock.unlock() }

        let access = WorseQuery.grantAccess(to: path, using: appGroupIdentifier)
        guard access.succeeded else {
            return DirectoryLoadResult(
                handle: nil,
                entries: [],
                error: "Worse Query failed (\(access.handle)): \(access.message)"
            )
        }

        do {
            let urls = try FileManager.default.contentsOfDirectory(
                at: URL(fileURLWithPath: path, isDirectory: true),
                includingPropertiesForKeys: [.isDirectoryKey, .isHiddenKey, .fileSizeKey, .contentModificationDateKey],
                options: []
            )

            let entries = urls.map { url -> BrowserFile in
                let values = try? url.resourceValues(forKeys: [
                    .isDirectoryKey,
                    .isHiddenKey,
                    .fileSizeKey,
                    .contentModificationDateKey
                ])
                return BrowserFile(
                    path: url.path,
                    name: url.lastPathComponent,
                    isDirectory: values?.isDirectory ?? false,
                    isHidden: values?.isHidden ?? url.lastPathComponent.hasPrefix("."),
                    byteCount: Int64(values?.fileSize ?? 0),
                    modifiedAt: values?.contentModificationDate
                )
            }.sorted { lhs, rhs in
                if lhs.isDirectory != rhs.isDirectory { return lhs.isDirectory }
                return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
            }

            // Keep the grant alive for the lifetime of the directory browser.
            return DirectoryLoadResult(handle: access.handle, entries: entries, error: nil)
        } catch {
            WorseQuery.release(access.handle)
            return DirectoryLoadResult(
                handle: nil,
                entries: [],
                error: "Directory read failed: \(error.localizedDescription)"
            )
        }
    }

    /// Lists an experimental system path using ordinary filesystem access only.
    /// This method deliberately does not request a Worse Query grant.
    static func listDirectoryDirect(at path: String) -> DirectoryLoadResult {
        var rootMetadata = stat()
        let rootStat = path.withCString { stat($0, &rootMetadata) }
        guard rootStat == 0,
              (rootMetadata.st_mode & mode_t(Darwin.S_IFMT)) == mode_t(Darwin.S_IFDIR) else {
            let message = rootStat == 0
                ? "The requested path is not a directory."
                : "Could not access directory (errno \(errno))."
            return DirectoryLoadResult(handle: nil, entries: [], error: message)
        }

        do {
            let names = try FileManager.default.contentsOfDirectory(atPath: path)
            var entries: [BrowserFile] = []
            entries.reserveCapacity(names.count)

            for name in names {
                let childPath = URL(fileURLWithPath: path, isDirectory: true)
                    .appendingPathComponent(name, isDirectory: false).path
                var metadata = stat()
                let childStat = childPath.withCString { lstat($0, &metadata) }
                guard childStat == 0 else { continue }

                let kind = metadata.st_mode & mode_t(Darwin.S_IFMT)
                let isDirectory = kind == mode_t(Darwin.S_IFDIR)
                let byteCount = kind == mode_t(Darwin.S_IFREG) && metadata.st_size > 0
                    ? Int64(metadata.st_size)
                    : 0
                let modifiedAt = Date(
                    timeIntervalSince1970: TimeInterval(metadata.st_mtimespec.tv_sec)
                        + TimeInterval(metadata.st_mtimespec.tv_nsec) / 1_000_000_000
                )

                entries.append(BrowserFile(
                    path: childPath,
                    name: name,
                    isDirectory: isDirectory,
                    isHidden: name.hasPrefix("."),
                    byteCount: byteCount,
                    modifiedAt: modifiedAt
                ))
            }

            entries.sort { lhs, rhs in
                if lhs.isDirectory != rhs.isDirectory { return lhs.isDirectory }
                return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
            }
            return DirectoryLoadResult(handle: nil, entries: entries, error: nil)
        } catch {
            return DirectoryLoadResult(
                handle: nil,
                entries: [],
                error: "Direct directory read failed: \(error.localizedDescription)"
            )
        }
    }

    static func directoryContentSize(at path: String, appGroupIdentifier: String) -> Int64? {
        operationLock.lock()
        defer { operationLock.unlock() }

        return try? FolderContentSizeReader.calculate(
            at: URL(fileURLWithPath: path, isDirectory: true),
            appGroupIdentifier: appGroupIdentifier
        )
    }

    /// Creates a ZIP containing every discovered container in the selected
    /// section. Each directory and file receives a path-scoped Worse Query grant.
    static func createSectionArchive(
        root: ContainerRoot,
        entries: [ContainerEntry],
        appGroupIdentifier: String
    ) throws -> URL {
        operationLock.lock()
        defer { operationLock.unlock() }

        let archiveName = "worsewatched-\(safeArchiveComponent(root.title))-\(Int(Date().timeIntervalSince1970)).zip"
        let archiveURL = FileManager.default.temporaryDirectory.appendingPathComponent(archiveName)
        try? FileManager.default.removeItem(at: archiveURL)

        do {
            let writer = try StoredZIPWriter(destination: archiveURL)
            try writer.addDirectory("\(safeArchiveComponent(root.title))/")

            let displayNameCounts = Dictionary(grouping: entries, by: \.displayName)
            var visitedEntries = 0
            for entry in entries {
                let baseName = entry.displayName == "Identifier unavailable"
                    ? URL(fileURLWithPath: entry.path).lastPathComponent
                    : entry.displayName
                let uniqueName: String
                if (displayNameCounts[entry.displayName]?.count ?? 0) > 1 {
                    uniqueName = "\(baseName) (\(URL(fileURLWithPath: entry.path).lastPathComponent))"
                } else {
                    uniqueName = baseName
                }

                let containerPrefix = "\(safeArchiveComponent(root.title))/\(safeArchiveComponent(uniqueName))"
                try writer.addDirectory(containerPrefix + "/")
                try archiveDirectory(
                    at: entry.path,
                    archivePrefix: containerPrefix,
                    appGroupIdentifier: appGroupIdentifier,
                    writer: writer,
                    depth: 0,
                    visitedEntries: &visitedEntries
                )
            }

            try writer.finish()
            return archiveURL
        } catch {
            try? FileManager.default.removeItem(at: archiveURL)
            throw error
        }
    }

    private static func archiveDirectory(
        at path: String,
        archivePrefix: String,
        appGroupIdentifier: String,
        writer: StoredZIPWriter,
        depth: Int,
        visitedEntries: inout Int
    ) throws {
        let maximumDepth = 64
        let maximumEntries = 250_000
        guard depth <= maximumDepth else {
            throw NSError(domain: "WorseWatched.Export", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "The section is deeper than the export limit."])
        }

        let directoryGrant = WorseQuery.grantAccess(to: path, using: appGroupIdentifier)
        guard directoryGrant.succeeded else {
            throw NSError(domain: "WorseWatched.Export", code: Int(directoryGrant.handle),
                          userInfo: [NSLocalizedDescriptionKey: "Could not access directory \(path): \(directoryGrant.message)"])
        }

        struct Child {
            let name: String
            let path: String
            let isDirectory: Bool
            let isRegularFile: Bool
        }

        let children: [Child]
        do {
            let names = try FileManager.default.contentsOfDirectory(atPath: path)
            visitedEntries += names.count
            guard visitedEntries <= maximumEntries else {
                throw NSError(domain: "WorseWatched.Export", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "The section contains more than \(maximumEntries) items."])
            }

            var discovered: [Child] = []
            discovered.reserveCapacity(names.count)
            for name in names {
                let childPath = URL(fileURLWithPath: path, isDirectory: true)
                    .appendingPathComponent(name, isDirectory: false).path
                var metadata = stat()
                let result = childPath.withCString { lstat($0, &metadata) }
                guard result == 0 else {
                    if errno == ENOENT { continue }
                    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
                }

                let kind = metadata.st_mode & mode_t(Darwin.S_IFMT)
                // Never follow symlinks or package special filesystem objects.
                if kind == mode_t(Darwin.S_IFLNK) { continue }
                discovered.append(Child(
                    name: name,
                    path: childPath,
                    isDirectory: kind == mode_t(Darwin.S_IFDIR),
                    isRegularFile: kind == mode_t(Darwin.S_IFREG)
                ))
            }
            children = discovered
            WorseQuery.release(directoryGrant.handle)
        } catch {
            WorseQuery.release(directoryGrant.handle)
            throw error
        }

        for child in children {
            let archivePath = archivePrefix + "/" + safeArchiveComponent(child.name)
            if child.isDirectory {
                try writer.addDirectory(archivePath + "/")
                try archiveDirectory(
                    at: child.path,
                    archivePrefix: archivePath,
                    appGroupIdentifier: appGroupIdentifier,
                    writer: writer,
                    depth: depth + 1,
                    visitedEntries: &visitedEntries
                )
            } else if child.isRegularFile {
                try writer.addFile(
                    archivePath,
                    sourcePath: child.path,
                    parentPath: path,
                    appGroupIdentifier: appGroupIdentifier
                )
            }
        }
    }

    private static func safeArchiveComponent(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != ".", trimmed != ".." else { return "_" }
        return trimmed
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "\\", with: "_")
    }

    /// Reads a regular file through the process's existing filesystem access.
    /// No Worse Query call is made for experimental direct paths.
    static func readFileDirect(at path: String) -> FileReadResult {
        let maximumPreviewSize: Int64 = 4 * 1024 * 1024
        let descriptor = path.withCString {
            Darwin.open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            return FileReadResult(
                data: nil,
                byteCount: 0,
                error: "Direct file open failed (errno \(errno))."
            )
        }
        defer { Darwin.close(descriptor) }

        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & mode_t(Darwin.S_IFMT)) == mode_t(Darwin.S_IFREG) else {
            return FileReadResult(
                data: nil,
                byteCount: 0,
                error: "The selected item is not a regular file."
            )
        }

        let byteCount = max(0, Int64(metadata.st_size))
        guard byteCount <= maximumPreviewSize else {
            return FileReadResult(
                data: nil,
                byteCount: byteCount,
                error: "File is too large for an in-app preview (limit: 4 MB)."
            )
        }

        var data = Data()
        data.reserveCapacity(Int(byteCount))
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let bytesRead = buffer.withUnsafeMutableBufferPointer { pointer in
                Darwin.read(descriptor, pointer.baseAddress, pointer.count)
            }
            if bytesRead == 0 { break }
            if bytesRead < 0 {
                if errno == EINTR { continue }
                return FileReadResult(
                    data: nil,
                    byteCount: byteCount,
                    error: "Direct file read failed (errno \(errno))."
                )
            }
            if data.count + bytesRead > Int(maximumPreviewSize) {
                return FileReadResult(
                    data: nil,
                    byteCount: Int64(data.count + bytesRead),
                    error: "File is too large for an in-app preview (limit: 4 MB)."
                )
            }
            data.append(contentsOf: buffer[0..<bytesRead])
        }

        return FileReadResult(data: data, byteCount: Int64(data.count), error: nil)
    }

    static func readFile(at path: String, parentPath: String, appGroupIdentifier: String) -> FileReadResult {
        operationLock.lock()
        defer { operationLock.unlock() }

        let fileURL = URL(fileURLWithPath: path)
        let maximumPreviewSize: Int64 = 4 * 1024 * 1024

        func readWhileGranted(_ handle: Int64) -> FileReadResult {
            defer { WorseQuery.release(handle) }
            let attributes = try? FileManager.default.attributesOfItem(atPath: path)
            let byteCount = (attributes?[.size] as? NSNumber)?.int64Value ?? 0
            guard byteCount <= maximumPreviewSize else {
                return FileReadResult(
                    data: nil,
                    byteCount: byteCount,
                    error: "File is too large for an in-app preview (limit: 4 MB)."
                )
            }
            do {
                let data = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
                guard Int64(data.count) <= maximumPreviewSize else {
                    return FileReadResult(
                        data: nil,
                        byteCount: Int64(data.count),
                        error: "File is too large for an in-app preview (limit: 4 MB)."
                    )
                }
                return FileReadResult(data: data, byteCount: Int64(data.count), error: nil)
            } catch {
                return FileReadResult(data: nil, byteCount: byteCount, error: error.localizedDescription)
            }
        }

        // Try the file itself first, matching Erosion's per-item Worse Query reads.
        let directAccess = WorseQuery.grantAccess(to: path, using: appGroupIdentifier)
        var directResult: FileReadResult?
        if directAccess.succeeded {
            directResult = readWhileGranted(directAccess.handle)
            if let result = directResult,
               result.data != nil || result.error?.contains("too large") == true {
                return result
            }
        }

        // Some container layouts allow traversal through the parent even when
        // a direct file grant/read does not succeed.
        let parentAccess = WorseQuery.grantAccess(to: parentPath, using: appGroupIdentifier)
        guard parentAccess.succeeded else {
            return FileReadResult(
                data: nil,
                byteCount: directResult?.byteCount ?? 0,
                error: "File grant failed (\(directAccess.handle)); parent grant failed (\(parentAccess.handle)): \(parentAccess.message)"
            )
        }
        let parentResult = readWhileGranted(parentAccess.handle)
        if parentResult.data != nil { return parentResult }
        return FileReadResult(
            data: nil,
            byteCount: max(directResult?.byteCount ?? 0, parentResult.byteCount),
            error: "Direct file read: \(directResult?.error ?? directAccess.message). Parent read: \(parentResult.error ?? "failed")"
        )
    }
}

/// Dependency-free ZIP64 writer using the STORE method. Files are streamed in
/// chunks; the archive supports large sections without loading them into memory.
private final class StoredZIPWriter {
    private struct CentralRecord {
        let name: Data
        let crc32: UInt32
        let size: UInt64
        let localHeaderOffset: UInt64
        let usesDataDescriptor: Bool
        let isDirectory: Bool
    }

    private let handle: FileHandle
    private var records: [CentralRecord] = []
    private var isFinished = false
    private static let maximumRecords = 300_000

    init(destination: URL) throws {
        guard FileManager.default.createFile(atPath: destination.path, contents: Data()) else {
            throw NSError(domain: "WorseWatched.Export", code: 10,
                          userInfo: [NSLocalizedDescriptionKey: "Could not create the ZIP file."])
        }
        handle = try FileHandle(forWritingTo: destination)
    }

    func addDirectory(_ name: String) throws {
        let normalized = name.hasSuffix("/") ? name : name + "/"
        let nameData = Data(normalized.utf8)
        try validateNewRecord(nameData)
        let offset = handle.offsetInFile

        var header = Data()
        header.appendLE(UInt32(0x04034b50))
        header.appendLE(UInt16(20))
        header.appendLE(UInt16(0x0800)) // UTF-8 filename encoding
        header.appendLE(UInt16(0)) // STORE
        header.appendLE(UInt16(0))
        header.appendLE(UInt16(0))
        header.appendLE(UInt32(0))
        header.appendLE(UInt32(0))
        header.appendLE(UInt32(0))
        header.appendLE(UInt16(nameData.count))
        header.appendLE(UInt16(0))
        header.append(nameData)
        try handle.write(contentsOf: header)

        records.append(CentralRecord(
            name: nameData,
            crc32: 0,
            size: 0,
            localHeaderOffset: offset,
            usesDataDescriptor: false,
            isDirectory: true
        ))
    }

    func addFile(
        _ archiveName: String,
        sourcePath: String,
        parentPath: String,
        appGroupIdentifier: String
    ) throws {
        let nameData = Data(archiveName.utf8)
        try validateNewRecord(nameData)

        var grant = WorseQuery.grantAccess(to: sourcePath, using: appGroupIdentifier)
        if !grant.succeeded {
            grant = WorseQuery.grantAccess(to: parentPath, using: appGroupIdentifier)
        }
        guard grant.succeeded else {
            throw NSError(domain: "WorseWatched.Export", code: Int(grant.handle),
                          userInfo: [NSLocalizedDescriptionKey: "Could not access file \(sourcePath): \(grant.message)"])
        }
        defer { WorseQuery.release(grant.handle) }

        var metadata = stat()
        guard sourcePath.withCString({ lstat($0, &metadata) }) == 0,
              (metadata.st_mode & mode_t(Darwin.S_IFMT)) == mode_t(Darwin.S_IFREG) else {
            throw NSError(domain: "WorseWatched.Export", code: 11,
                          userInfo: [NSLocalizedDescriptionKey: "The file changed or is not a regular file: \(sourcePath)"])
        }

        let descriptor = Darwin.open(sourcePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw posixError() }
        defer { Darwin.close(descriptor) }

        var openedMetadata = stat()
        guard fstat(descriptor, &openedMetadata) == 0,
              (openedMetadata.st_mode & mode_t(Darwin.S_IFMT)) == mode_t(Darwin.S_IFREG),
              openedMetadata.st_dev == metadata.st_dev,
              openedMetadata.st_ino == metadata.st_ino else {
            throw NSError(domain: "WorseWatched.Export", code: 12,
                          userInfo: [NSLocalizedDescriptionKey: "The file changed while preparing export: \(sourcePath)"])
        }

        let localOffset = handle.offsetInFile
        let flags: UInt16 = 0x0808 // UTF-8 + data descriptor
        var header = Data()
        header.appendLE(UInt32(0x04034b50))
        header.appendLE(UInt16(45)) // ZIP64
        header.appendLE(flags)
        header.appendLE(UInt16(0)) // STORE; no compression
        header.appendLE(UInt16(0))
        header.appendLE(UInt16(0))
        header.appendLE(UInt32(0)) // CRC is written in the descriptor
        header.appendLE(UInt32.max) // ZIP64 size placeholders
        header.appendLE(UInt32.max)
        header.appendLE(UInt16(nameData.count))
        header.appendLE(UInt16(20)) // ZIP64 extra field length
        header.append(nameData)
        header.appendLE(UInt16(0x0001)) // ZIP64 extended information
        header.appendLE(UInt16(16))
        header.appendLE(UInt64(0)) // sizes supplied after streaming
        header.appendLE(UInt64(0))
        try handle.write(contentsOf: header)

        var crc = UInt32.max
        var totalSize: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let bytesRead = buffer.withUnsafeMutableBufferPointer { pointer in
                Darwin.read(descriptor, pointer.baseAddress, pointer.count)
            }
            if bytesRead == 0 { break }
            if bytesRead < 0 {
                if errno == EINTR { continue }
                throw posixError()
            }

            let (newTotalSize, overflow) = totalSize.addingReportingOverflow(UInt64(bytesRead))
            guard !overflow else {
                throw NSError(domain: "WorseWatched.Export", code: 13,
                              userInfo: [NSLocalizedDescriptionKey: "A file is too large to represent in a ZIP archive: \(sourcePath)"])
            }
            totalSize = newTotalSize
            crc = Self.updateCRC32(crc, bytes: buffer, count: bytesRead)
            try handle.write(contentsOf: Data(buffer[0..<bytesRead]))
        }

        let finalCRC = crc ^ UInt32.max
        var descriptorData = Data()
        descriptorData.appendLE(UInt32(0x08074b50))
        descriptorData.appendLE(finalCRC)
        descriptorData.appendLE(totalSize) // compressed size; STORE method
        descriptorData.appendLE(totalSize) // uncompressed size
        try handle.write(contentsOf: descriptorData)

        records.append(CentralRecord(
            name: nameData,
            crc32: finalCRC,
            size: totalSize,
            localHeaderOffset: localOffset,
            usesDataDescriptor: true,
            isDirectory: false
        ))
    }

    func finish() throws {
        guard !isFinished else { return }
        let centralOffset = handle.offsetInFile

        for record in records {
            var central = Data()
            central.appendLE(UInt32(0x02014b50))
            central.appendLE(UInt16(45)) // made by ZIP64
            central.appendLE(UInt16(45)) // required version
            central.appendLE(record.usesDataDescriptor ? UInt16(0x0808) : UInt16(0x0800))
            central.appendLE(UInt16(0)) // STORE
            central.appendLE(UInt16(0))
            central.appendLE(UInt16(0))
            central.appendLE(record.crc32)
            central.appendLE(record.isDirectory ? UInt32(0) : UInt32.max)
            central.appendLE(record.isDirectory ? UInt32(0) : UInt32.max)
            central.appendLE(UInt16(record.name.count))
            central.appendLE(record.isDirectory ? UInt16(12) : UInt16(28))
            central.appendLE(UInt16(0)) // comment length
            central.appendLE(UInt16(0)) // disk number
            central.appendLE(UInt16(0)) // internal attributes
            central.appendLE(record.isDirectory ? UInt32(0x10) : UInt32(0))
            central.appendLE(UInt32.max) // offset is stored in ZIP64 extra
            central.append(record.name)
            central.appendLE(UInt16(0x0001))
            central.appendLE(record.isDirectory ? UInt16(8) : UInt16(24))
            if !record.isDirectory {
                central.appendLE(record.size) // uncompressed size
                central.appendLE(record.size) // compressed size (STORE)
            }
            central.appendLE(record.localHeaderOffset)
            try handle.write(contentsOf: central)
        }

        let centralEnd = handle.offsetInFile
        let centralSize = centralEnd - centralOffset
        let zip64EndOffset = handle.offsetInFile

        var zip64End = Data()
        zip64End.appendLE(UInt32(0x06064b50))
        zip64End.appendLE(UInt64(44)) // bytes following this size field
        zip64End.appendLE(UInt16(45))
        zip64End.appendLE(UInt16(45))
        zip64End.appendLE(UInt32(0))
        zip64End.appendLE(UInt32(0))
        zip64End.appendLE(UInt64(records.count))
        zip64End.appendLE(UInt64(records.count))
        zip64End.appendLE(centralSize)
        zip64End.appendLE(centralOffset)
        try handle.write(contentsOf: zip64End)

        var zip64Locator = Data()
        zip64Locator.appendLE(UInt32(0x07064b50))
        zip64Locator.appendLE(UInt32(0))
        zip64Locator.appendLE(zip64EndOffset)
        zip64Locator.appendLE(UInt32(1))
        try handle.write(contentsOf: zip64Locator)

        // Classic EOCD is retained with sentinel values, as ZIP64 requires.
        var end = Data()
        end.appendLE(UInt32(0x06054b50))
        end.appendLE(UInt16(0))
        end.appendLE(UInt16(0))
        end.appendLE(UInt16.max)
        end.appendLE(UInt16.max)
        end.appendLE(UInt32.max)
        end.appendLE(UInt32.max)
        end.appendLE(UInt16(0))
        try handle.write(contentsOf: end)
        try handle.close()
        isFinished = true
    }

    private func validateNewRecord(_ name: Data) throws {
        guard !isFinished,
              name.count <= Int(UInt16.max),
              records.count < Self.maximumRecords else {
            throw NSError(domain: "WorseWatched.Export", code: 16,
                          userInfo: [NSLocalizedDescriptionKey: "The entry name is too long or the section has too many entries."])
        }
    }

    private func posixError() -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }

    private static func updateCRC32(_ current: UInt32, bytes: [UInt8], count: Int) -> UInt32 {
        var crc = current
        for index in 0..<count {
            crc = (crc >> 8) ^ crcTable[Int((crc ^ UInt32(bytes[index])) & 0xff)]
        }
        return crc
    }

    private static let crcTable: [UInt32] = (0..<256).map { value in
        var crc = UInt32(value)
        for _ in 0..<8 {
            crc = (crc & 1) == 1 ? (0xedb88320 ^ (crc >> 1)) : (crc >> 1)
        }
        return crc
    }

    deinit {
        try? handle.close()
    }
}

private extension Data {
    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        var littleEndianValue = value.littleEndian
        Swift.withUnsafeBytes(of: &littleEndianValue) { bytes in
            append(contentsOf: bytes)
        }
    }
}

/// Aggregate directory-size calculation adapted from Erosion's
/// FolderContentSizeReader. Each directory receives its own Worse Query grant,
/// matching the way the browser opens nested folders. Symlinks and special
/// filesystem entries are skipped; every regular file contributes its logical size.
private enum FolderContentSizeReader {
    private static let maximumDepth = 64
    private static let maximumEntries = 200_000

    static func calculate(at url: URL, appGroupIdentifier: String) throws -> Int64 {
        var visitedEntries = 0
        return try directorySize(
            at: url,
            appGroupIdentifier: appGroupIdentifier,
            depth: 0,
            visitedEntries: &visitedEntries
        )
    }

    private static func directorySize(
        at url: URL,
        appGroupIdentifier: String,
        depth: Int,
        visitedEntries: inout Int
    ) throws -> Int64 {
        guard depth <= maximumDepth else { throw CocoaError(.fileReadTooLarge) }

        // Worse Query is path-scoped. Request access at every level instead of
        // assuming that a grant to the container root covers every descendant.
        let access = WorseQuery.grantAccess(to: url.path, using: appGroupIdentifier)
        guard access.succeeded else {
            throw NSError(
                domain: "WorseWatched.DirectorySize",
                code: Int(access.handle),
                userInfo: [NSLocalizedDescriptionKey: access.message]
            )
        }
        defer { WorseQuery.release(access.handle) }

        // Re-check the directory without following a possible symlink swap.
        var rootMetadata = stat()
        let rootStatResult = url.path.withCString { path in
            lstat(path, &rootMetadata)
        }
        guard rootStatResult == 0,
              (rootMetadata.st_mode & mode_t(Darwin.S_IFMT)) == mode_t(Darwin.S_IFDIR) else {
            throw CocoaError(.fileReadUnsupportedScheme)
        }

        let childNames = try FileManager.default.contentsOfDirectory(atPath: url.path)
        var total: Int64 = 0

        for name in childNames {
            if name == "." || name == ".." { continue }

            visitedEntries += 1
            guard visitedEntries <= maximumEntries else {
                throw CocoaError(.fileReadTooLarge)
            }

            let childURL = url.appendingPathComponent(name, isDirectory: false)
            var metadata = stat()
            let statResult = childURL.path.withCString { path in
                lstat(path, &metadata)
            }
            guard statResult == 0 else {
                // Ignore an item that disappeared during the size walk, but do
                // not silently claim a complete size for other filesystem errors.
                if errno == ENOENT { continue }
                throw posixError()
            }

            let kind = metadata.st_mode & mode_t(Darwin.S_IFMT)
            if kind == mode_t(Darwin.S_IFLNK) {
                continue
            } else if kind == mode_t(Darwin.S_IFDIR) {
                let childSize = try directorySize(
                    at: childURL,
                    appGroupIdentifier: appGroupIdentifier,
                    depth: depth + 1,
                    visitedEntries: &visitedEntries
                )
                let (sum, overflow) = total.addingReportingOverflow(childSize)
                guard !overflow else { throw CocoaError(.fileReadTooLarge) }
                total = sum
            } else if kind == mode_t(Darwin.S_IFREG) {
                guard metadata.st_size >= 0 else { throw posixError() }
                let (sum, overflow) = total.addingReportingOverflow(Int64(metadata.st_size))
                guard !overflow else { throw CocoaError(.fileReadTooLarge) }
                total = sum
            }
            // Sockets, devices, FIFOs and other special entries add no file data.
        }

        return total
    }

    private static func posixError() -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
}

final class ScanEngine: ObservableObject {
    @Published private(set) var results = ContainerRoot.supported.map { ContainerScanResult(root: $0) }
    @Published private(set) var logs: [String] = []
    @Published private(set) var isScanning = false
    // Worse Query temporarily repoints the same App Group Caches path for every
    // request, so all per-container grants must be strictly serial.
    private let scanQueue = DispatchQueue(
        label: "com.ceoca.worsewatch.scan-queue",
        qos: .userInitiated
    )
    private var didStartInitialScan = false

    func scanOnLaunch() {
        guard !didStartInitialScan else { return }
        didStartInitialScan = true
        scan()
    }

    func createArchive(for root: ContainerRoot) async throws -> URL {
        guard let appGroupIdentifier = WorseQuery.getAppGroupIdentifier() else {
            throw NSError(domain: "WorseWatched.Export", code: 20,
                          userInfo: [NSLocalizedDescriptionKey: "No sideloader App Group entitlement is available."])
        }
        guard let result = results.first(where: { $0.root.id == root.id }), !result.entries.isEmpty else {
            throw NSError(domain: "WorseWatched.Export", code: 21,
                          userInfo: [NSLocalizedDescriptionKey: "There are no scanned containers in this section."])
        }

        let capturedRoot = result.root
        let capturedEntries = result.entries
        return try await Task.detached(priority: .utility) {
            try ContainerFileAccess.createSectionArchive(
                root: capturedRoot,
                entries: capturedEntries,
                appGroupIdentifier: appGroupIdentifier
            )
        }.value
    }

    func scan() {
        guard !isScanning else {
            appendLog("[!] A scan is already running; ignored the extra request.")
            return
        }

        let supportedRoots = ContainerRoot.supported
        let directRoots = supportedRoots.filter { $0.usesDirectAccess }
        let containerRoots = supportedRoots.filter { !$0.usesDirectAccess }

        isScanning = true
        results = supportedRoots.map { ContainerScanResult(root: $0, status: "Scanning…") }
        logs = []
        appendLog("[*] worsewatched started")
        appendLog("[*] Direct paths will be read without Worse Query")

        scanQueue.async { [weak self] in
            guard let self else { return }
            var resultsByID: [String: ContainerScanResult] = [:]

            for root in directRoots {
                resultsByID[root.id] = Self.scanDirectRoot(root) {
                    self.appendLog($0)
                }
            }

            // Resolve the sideloader entitlement only after the direct roots have
            // been enumerated; direct paths do not depend on Worse Query at all.
            let appGroupIdentifier = containerRoots.isEmpty
                ? nil
                : WorseQuery.getAppGroupIdentifier()

            if let appGroupIdentifier {
                self.appendLog("[*] App Group: \(appGroupIdentifier)")
                self.appendLog("[*] Discovering container roots through pathleak and Worse Query")
                guard let inodeLimit = Self.makeInodeLimit(log: { self.appendLog($0) }) else {
                    for root in containerRoots {
                        resultsByID[root.id] = ContainerScanResult(
                            root: root,
                            status: "Could not create inode baseline"
                        )
                    }
                    let completed = supportedRoots.compactMap { resultsByID[$0.id] }
                    self.finishScan(with: completed)
                    return
                }

                for root in containerRoots {
                    resultsByID[root.id] = Self.scanRoot(
                        root,
                        inodeLimit: inodeLimit,
                        appGroupIdentifier: appGroupIdentifier
                    ) {
                        self.appendLog($0)
                    }
                }
            } else {
                if !containerRoots.isEmpty {
                    self.appendLog("[!] No sideloader App Group entitlement; container scans will be skipped")
                }
                for root in containerRoots {
                    resultsByID[root.id] = ContainerScanResult(
                        root: root,
                        status: "No sideloader App Group entitlement"
                    )
                }
            }

            let completed = supportedRoots.compactMap { resultsByID[$0.id] }
            self.finishScan(with: completed)
        }
    }

    private static func scanDirectRoot(
        _ root: ContainerRoot,
        log: (String) -> Void
    ) -> ContainerScanResult {
        log("[*] Directly enumerating \(root.path)")
        let listing = ContainerFileAccess.listDirectoryDirect(at: root.path)
        guard listing.error == nil else {
            let detail = listing.error ?? "Unknown direct-access error"
            log("[!] \(root.path): \(detail)")
            return ContainerScanResult(root: root, status: detail)
        }

        let entries = listing.entries.map { item in
            ContainerEntry(
                path: item.path,
                displayName: item.name,
                creationDate: item.modifiedAt
            )
        }
        log("[+] \(root.path): \(entries.count) immediate item(s), direct access")
        return ContainerScanResult(
            root: root,
            entries: entries,
            status: "\(entries.count) item(s)"
        )
    }

    private func finishScan(with completedResults: [ContainerScanResult]) {
        DispatchQueue.main.async {
            self.results = completedResults
            self.isScanning = false
            let containerCount = completedResults
                .filter { !$0.root.usesDirectAccess }
                .reduce(0) { $0 + $1.entries.count }
            let directItemCount = completedResults
                .filter { $0.root.usesDirectAccess }
                .reduce(0) { $0 + $1.entries.count }
            self.appendLog("[*] Scan finished: \(containerCount) container(s), \(directItemCount) direct path item(s)")
        }
    }

    private func appendLog(_ line: String) {
        let cleanedLine = line
            .replacingOccurrences(
                of: #"^\s*(?:\[[^\]]+\]\s*)+"#,
                with: "",
                options: .regularExpression
            )
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanedLine.isEmpty else { return }

        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.logs.append(cleanedLine)
            if self.logs.count > 120 {
                self.logs.removeFirst(self.logs.count - 120)
            }
        }
    }

    /// Restored exactly to the original behavior: create a temporary file and
    /// use its inode number as pathleak's upper bound.
    private static func makeInodeLimit(log: (String) -> Void) -> UInt64? {
        let baselineURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(".worsewatched-baseline-\(UUID().uuidString)")

        do {
            try "worsewatched".write(to: baselineURL, atomically: true, encoding: .utf8)
            var baselineInfo = stat()
            guard stat(baselineURL.path, &baselineInfo) == 0 else {
                try? FileManager.default.removeItem(at: baselineURL)
                log("[!] Could not get the baseline inode for pathleak")
                return nil
            }
            try? FileManager.default.removeItem(at: baselineURL)
            let limit = UInt64(baselineInfo.st_ino)
            log("[*] pathleak inode limit: \(limit)")
            return limit
        } catch {
            try? FileManager.default.removeItem(at: baselineURL)
            log("[!] Could not create pathleak baseline: \(error.localizedDescription)")
            return nil
        }
    }

    private static func readMCMIdentifier(
        at containerPath: String,
        appGroupIdentifier: String
    ) -> (identifier: String?, detail: String) {
        let containerURL = URL(fileURLWithPath: containerPath, isDirectory: true)
        let metadataFiles = [
            ".com.apple.mobile_container_manager.metadata.plist",
            "com.apple.mobile_container_manager.metadata.plist"
        ]
        var attempts: [String] = []

        for fileName in metadataFiles {
            let metadataURL = containerURL.appendingPathComponent(fileName)
            // Erosion's readMetaKey asks Worse Query for the metadata file itself,
            // rather than assuming that a grant to its parent is sufficient.
            let metadataAccess = WorseQuery.grantAccess(
                to: metadataURL.path,
                using: appGroupIdentifier
            )
            guard metadataAccess.succeeded else {
                attempts.append("\(fileName): Worse Query grant failed (\(metadataAccess.handle))")
                continue
            }

            let parsedIdentifier: String?
            do {
                let data = try Data(contentsOf: metadataURL)
                let object = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
                let dictionary = object as? [String: Any]
                parsedIdentifier = (dictionary?["MCMMetadataIdentifier"] as? String)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
            } catch {
                WorseQuery.release(metadataAccess.handle)
                attempts.append("\(fileName): metadata read/parse failed (\(error.localizedDescription))")
                continue
            }
            WorseQuery.release(metadataAccess.handle)

            if let parsedIdentifier, !parsedIdentifier.isEmpty {
                return (parsedIdentifier, "\(fileName): MCMMetadataIdentifier")
            }
            attempts.append("\(fileName): MCMMetadataIdentifier missing or empty")
        }

        // Erosion's File Browser also uses this MCM xattr as its folder-label path.
        // The caller still holds the directory grant while this xattr is read.
        var buffer = [CChar](repeating: 0, count: 512)
        let length = buffer.withUnsafeMutableBufferPointer { pointer in
            getxattr(
                containerPath,
                "com.apple.containermanager.identifier",
                pointer.baseAddress,
                pointer.count - 1,
                0,
                XATTR_NOFOLLOW
            )
        }
        if length > 0 {
            let identifier = String(cString: buffer)
            if !identifier.isEmpty {
                return (identifier, "com.apple.containermanager.identifier xattr")
            }
        }
        attempts.append("com.apple.containermanager.identifier xattr unavailable")
        return (nil, attempts.joined(separator: " | "))
    }

    private static func scanRoot(
        _ root: ContainerRoot,
        inodeLimit: UInt64,
        appGroupIdentifier: String,
        log: (String) -> Void
    ) -> ContainerScanResult {
        log("[*] Enumerating direct children: \(root.path)")

        guard let discoveredPaths = pathleak(root.enumerationPath, inodeLimit) else {
            log("[!] pathleak could not enumerate \(root.path)")
            return ContainerScanResult(root: root, status: "pathleak enumeration failed")
        }

        let sortedPaths = discoveredPaths.sorted {
            $0.localizedStandardCompare($1) == .orderedAscending
        }
        log("[+] pathleak found \(sortedPaths.count) direct path(s)")

        var accessibleEntries: [ContainerEntry] = []
        var failedCount = 0
        var unresolvedCount = 0
        var loggedFailures = 0

        for discoveredPath in sortedPaths {
            let name = URL(fileURLWithPath: discoveredPath).lastPathComponent
            guard !name.isEmpty else { continue }

            // Rebuild from the requested root to preserve the /private/var alias
            // used by Erosion for Shared/AppGroup queries.
            let candidatePath = URL(fileURLWithPath: root.path, isDirectory: true)
                .appendingPathComponent(name, isDirectory: true)
                .path

            let access = WorseQuery.grantAccess(to: candidatePath, using: appGroupIdentifier)
            guard access.succeeded else {
                failedCount += 1
                if loggedFailures < 5 {
                    log("[!] Worse Query rejected \(name) (\(access.handle)): \(access.message)")
                    loggedFailures += 1
                }
                continue
            }

            // Both the directory check and metadata read happen while its
            // Worse Query extension is active, then the grant is released.
            var candidateMetadata = stat()
            let hasDirectoryMetadata = candidatePath.withCString { path in
                lstat(path, &candidateMetadata) == 0
            }
            let isDirectory = hasDirectoryMetadata
                && (candidateMetadata.st_mode & mode_t(Darwin.S_IFMT)) == mode_t(Darwin.S_IFDIR)
            guard isDirectory else {
                WorseQuery.release(access.handle)
                continue
            }

            let metadata = readMCMIdentifier(at: candidatePath, appGroupIdentifier: appGroupIdentifier)
            let creationDate = Date(
                timeIntervalSince1970: TimeInterval(candidateMetadata.st_birthtimespec.tv_sec)
                    + TimeInterval(candidateMetadata.st_birthtimespec.tv_nsec) / 1_000_000_000
            )

            // Aggregate size is calculated lazily when the user opens this
            // category, so a large Application tree does not delay app launch.
            WorseQuery.release(access.handle)

            let displayName = metadata.identifier ?? "Identifier unavailable"
            if metadata.identifier == nil {
                unresolvedCount += 1
                if unresolvedCount <= 5 {
                    log("[!] No MCM bundle identifier for \(name): \(metadata.detail)")
                }
            }
            accessibleEntries.append(
                ContainerEntry(
                    path: candidatePath,
                    displayName: displayName,
                    creationDate: hasDirectoryMetadata ? creationDate : nil
                )
            )
        }

        let uniqueEntries = Dictionary(grouping: accessibleEntries, by: \.path)
            .compactMap { $0.value.first }
            .sorted { $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending }

        log("[+] \(root.title): \(uniqueEntries.count) directory(ies), \(unresolvedCount) without MCM identifier, \(failedCount) rejected")
        let status: String
        if uniqueEntries.isEmpty {
            status = failedCount > 0
                ? "No containers passed Worse Query (\(failedCount) rejected)"
                : "No direct containers discovered"
        } else {
            status = "\(uniqueEntries.count) containers"
        }
        return ContainerScanResult(root: root, entries: uniqueEntries, status: status)
    }
}
