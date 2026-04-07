import Foundation

/// Compute the claim cost in zatoshis for a name of the given length.
///
/// - Parameters:
///   - tiers: The pricing tiers from `StatusResult.pricing.tiers` (already in zatoshis).
///            Index 0 = 1-char names, index 1 = 2-char, etc.
///            Names longer than the array clamp to the last entry.
///   - nameLength: Character length of the name (must be >= 1).
/// - Returns: Cost in zatoshis, or `nil` if tiers is empty.
public func claimCost(tiers: [Int], nameLength: Int) -> Int? {
    guard !tiers.isEmpty else { return nil }
    let idx = min(max(nameLength - 1, 0), tiers.count - 1)
    return tiers[idx]
}
