//! ZNS claim-cost helpers.
//!
//! Claim costs are dynamic — published via the indexer's SETPRICE
//! actions and exposed through [`crate::Client::status`] as a
//! [`Pricing`] struct. This module is the pure-function lookup layer:
//! given a name length and the current pricing tiers, return the cost
//! in zatoshis.

use crate::types::Pricing;

/// Claim cost in zatoshis for a name of `length` characters.
///
/// Looks up `length - 1` in [`Pricing::tiers`]. Names longer than the
/// tier array fall back to the last (cheapest) tier, matching the
/// indexer's own pricing policy. Returns `None` only if `length == 0`
/// or the tier array is empty.
pub fn claim_cost(length: usize, pricing: &Pricing) -> Option<u64> {
    if length == 0 || pricing.tiers.is_empty() {
        return None;
    }
    let idx = (length - 1).min(pricing.tiers.len() - 1);
    Some(pricing.tiers[idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pricing() -> Pricing {
        Pricing {
            nonce: 1,
            height: 3_900_000,
            tiers: vec![
                600_000_000, // 1 char
                425_000_000, // 2 chars
                300_000_000, // 3 chars
                150_000_000, // 4 chars
                75_000_000,  // 5 chars
                50_000_000,  // 6 chars
                25_000_000,  // 7+ chars
            ],
        }
    }

    #[test]
    fn length_1_hits_tier_0() {
        assert_eq!(claim_cost(1, &sample_pricing()), Some(600_000_000));
    }

    #[test]
    fn length_5_hits_tier_4() {
        assert_eq!(claim_cost(5, &sample_pricing()), Some(75_000_000));
    }

    #[test]
    fn length_7_hits_last_tier() {
        assert_eq!(claim_cost(7, &sample_pricing()), Some(25_000_000));
    }

    #[test]
    fn long_names_fall_back_to_last_tier() {
        assert_eq!(claim_cost(62, &sample_pricing()), Some(25_000_000));
    }

    #[test]
    fn zero_length_returns_none() {
        assert_eq!(claim_cost(0, &sample_pricing()), None);
    }

    #[test]
    fn empty_tiers_returns_none() {
        let empty = Pricing {
            nonce: 0,
            height: 0,
            tiers: vec![],
        };
        assert_eq!(claim_cost(5, &empty), None);
    }
}
