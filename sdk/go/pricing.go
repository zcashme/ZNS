package zns

// ClaimCost calculates the cost in zatoshis to claim a name of the given length
// using the provided pricing tiers.
//
// Index 0 corresponds to 1-character names. If the name length exceeds the
// number of tiers, the last tier price is used. Returns nil if tiers is empty.
func ClaimCost(tiers []int, nameLength int) *int {
	if len(tiers) == 0 {
		return nil
	}
	if nameLength < 1 {
		return nil
	}

	idx := nameLength - 1
	if idx >= len(tiers) {
		idx = len(tiers) - 1
	}

	cost := tiers[idx]
	return &cost
}
