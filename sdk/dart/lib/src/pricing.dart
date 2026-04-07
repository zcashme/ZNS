/// Compute the claim cost in zatoshis for a name of the given length.
///
/// [tiers] comes from `StatusResult.pricing.tiers` (already in zatoshis).
/// Index 0 corresponds to 1-char names, index 1 to 2-char names, etc.
/// Names longer than the list clamp to the last entry.
///
/// Returns `null` if [tiers] is empty.
int? claimCost(List<int> tiers, int nameLength) {
  if (tiers.isEmpty) return null;
  final idx = (nameLength - 1).clamp(0, tiers.length - 1);
  return tiers[idx];
}
