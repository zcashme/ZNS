import Foundation

/// Validate a ZNS name.
///
/// Rules:
/// - 1 to 62 characters
/// - Lowercase ASCII letters (a-z) and digits (0-9) only
/// - No hyphens, no underscores, no unicode
///
/// - Parameter name: The name to validate.
/// - Returns: `true` if the name is valid.
public func isValidName(_ name: String) -> Bool {
    guard let regex = try? NSRegularExpression(pattern: "^[a-z0-9]{1,62}$") else {
        return false
    }
    let range = NSRange(name.startIndex..., in: name)
    return regex.firstMatch(in: name, range: range) != nil
}
