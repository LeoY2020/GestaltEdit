import Foundation
import Security

/// Persists the device's original MobileGestalt region values before the
/// "Enable Siri AI (US Region)" toggle overwrites them.
///
/// Storage uses the iOS Keychain rather than the App's sandbox because
/// Keychain items survive App uninstallation by default on iOS. This means
/// that even after deleting GestaltEdit, the original region can still be
/// restored by a future install. The Keychain entry is App-private (scoped
/// by service + account) and is not synced to iCloud, so it does not leave
/// "garbage" in any system file path.
///
/// Lifecycle:
/// - Save once, right before the first AI-region apply on a given device.
/// - Restore + clear when the user turns the toggle off.
/// - If a restore is requested but no backup exists (e.g. AI was enabled
///   by another tool), all affected keys are removed as a fallback so the
///   device returns to the "AI unconfigured" state instead of keeping a
///   half-applied spoof.
enum AIRegionBackupStore {
    private static let service = "me.ssus.gestaltedit.aiRegionBackup"
    private static let account = "originalRegionValues"

    /// All CacheExtra keys that the AI-region toggle may overwrite.
    /// Backing up and restoring this exact set keeps the device's state
    /// reversible.
    static let affectedKeys: [String] = [
        "h63QSdBCiT/z0WU6rdQv6Q", // RegionCode ("LL")
        "yK+xavymRGZ3xWc1tb8XDg", // RegionCodeWithSlash ("LL/A")
        "97JDvERpVwO+GHtthIh7hA", // RegulatoryModel
        "A62OafQ85EJAiiqKn4agtg", // DeviceIdentitySpoof flag
        "h9jDsbgj7xIVeIQ8S3/X3Q", // SpoofedProductType
        "oYicEKzVTz4/CxxE05pEgQ", // SpoofedHardwareModel
        "5pYKlGnYYBzGvAlIU8RjEQ"  // SpoofedCPUModel
    ]

    /// Snapshots the current values of ``affectedKeys`` from `plist` into
    /// the Keychain. A key that is absent in `plist` is recorded as
    /// "missing" so it can be removed on restore.
    static func save(from plist: GestaltPlist) throws {
        let cacheExtra = plist.cacheExtra
        // Wrap each entry as [present: Bool, data: base64-plist?].
        // PropertyListSerialization handles String / NSNumber / Data / Array
        // / Dictionary uniformly, so we do not need a per-type enum.
        var snapshot: [String: [String: Any]] = [:]
        for key in affectedKeys {
            if let value = cacheExtra[key] {
                let valueData = try PropertyListSerialization.data(
                    fromPropertyList: value,
                    format: .binary,
                    options: 0
                )
                snapshot[key] = [
                    "present": true,
                    "data": valueData.base64EncodedString()
                ]
            } else {
                snapshot[key] = ["present": false]
            }
        }
        let data = try PropertyListSerialization.data(
            fromPropertyList: snapshot,
            format: .binary,
            options: 0
        )
        try write(data: data)
    }

    /// Restores the snapshotted values back into `plist`. Keys that were
    /// originally missing are removed from CacheExtra; keys that had a
    /// value are written back. If no backup exists, all affected keys are
    /// removed as a fallback.
    static func restore(into plist: inout GestaltPlist) throws {
        guard let data = read() else {
            for key in affectedKeys {
                plist.removeCacheExtraValue(forKey: key)
            }
            return
        }

        let raw = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        )
        guard let snapshot = raw as? [String: [String: Any]] else {
            throw AIRegionBackupError.corruptBackup
        }

        for key in affectedKeys {
            guard let entry = snapshot[key] else {
                // Backed up before this key was tracked; leave as-is.
                continue
            }
            let present = entry["present"] as? Bool ?? false
            if present,
               let dataString = entry["data"] as? String,
               let valueData = Data(base64Encoded: dataString) {
                let value = try PropertyListSerialization.propertyList(
                    from: valueData,
                    options: [],
                    format: nil
                )
                plist.setCacheExtra(value, forKey: key)
            } else {
                plist.removeCacheExtraValue(forKey: key)
            }
        }
    }

    /// Deletes the Keychain entry. Safe to call when no backup exists.
    static func clear() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }

    static func hasBackup() -> Bool {
        read() != nil
    }

    // MARK: - Keychain primitives

    private static func write(data: Data) throws {
        clear()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecValueData as String: data
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw AIRegionBackupError.keychainWriteFailed(status: status)
        }
    }

    private static func read() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }
}

enum AIRegionBackupError: LocalizedError {
    case keychainWriteFailed(status: OSStatus)
    case corruptBackup

    var errorDescription: String? {
        switch self {
        case .keychainWriteFailed(let status):
            String(format: String(localized: "Failed to save AI region backup to Keychain (status %d)."), status)
        case .corruptBackup:
            String(localized: "The stored AI region backup is corrupt. The affected keys were removed; restore a plist backup manually if needed.")
        }
    }
}
