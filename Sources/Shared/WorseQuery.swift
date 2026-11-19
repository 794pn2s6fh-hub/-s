import Foundation

/// Worse Query wrapper. The sideloader can replace application-groups at signing time,
/// so never compile a sideloader or Erosion App Group identifier into this app.
enum WorseQuery {
    private static let queryLock = NSRecursiveLock()
    struct AccessResult {
        let succeeded: Bool
        let handle: Int64
        let message: String
    }

    /// Same runtime lookup used by Erosion's WorseQuery.getAppGroup().
    /// Called when a scan starts, after the installed app has been signed by its sideloader.
    static func getAppGroupIdentifier() -> String? {
        guard let task = SecTaskCreateFromSelf(nil),
              let entitlement = SecTaskCopyValueForEntitlement(
                task,
                "com.apple.security.application-groups" as CFString,
                nil
              ) else {
            return nil
        }

        let groups = entitlement as? [String] ?? []
        guard let selectedGroup = groups.first, !selectedGroup.isEmpty else {
            return nil
        }
        return selectedGroup
    }

    static func grantAccess(to path: String, using appGroupIdentifier: String) -> AccessResult {
        // Match Erosion's iOS 26 App Group flag handling.
        let isAppGroupPath = path.contains("/var/mobile/Containers/Shared/AppGroup")
        let useAlternateFlags = isAppGroupPath
            && ProcessInfo.processInfo.operatingSystemVersion.majorVersion == 26

        // worse_query temporarily replaces Library/Caches in the sideloader App Group.
        // Serialize calls from scanning and interactive directory/file browsing.
        queryLock.lock()
        let handle: Int64
        defer { queryLock.unlock() }
        handle = worse_query(
            path,
            appGroupIdentifier,
            useAlternateFlags,
            false
        )

        guard handle >= 0 else {
            let reason: String
            switch handle {
            case -1: reason = "could not resolve the current sideloader App Group container"
            case -2: reason = "container-manager or sandbox functions are unavailable"
            case -3: reason = "container query creation failed"
            case -4: reason = "temporary App Group Caches symlink creation failed"
            case -5: reason = "containermanagerd rejected the query"
            case -6: reason = "the kernel refused the sandbox extension"
            case -255: reason = "the requested path does not exist"
            default: reason = "Worse Query returned an unknown error"
            }
            return AccessResult(succeeded: false, handle: handle, message: reason)
        }

        return AccessResult(succeeded: true, handle: handle, message: "sandbox extension acquired")
    }

    static func release(_ handle: Int64) {
        guard handle >= 0 else { return }
        worse_query_release(handle)
    }
}
