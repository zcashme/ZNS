// ZNS state commitment — binary Merkle tree over registrations.
//
// Leaves are domain-separated, sorted by `name`, BLAKE2b-256 hashed. Internal
// nodes hash the concatenation of children with a separate domain tag. Odd
// levels duplicate the last node. The root is the chain-independent commitment
// to registry state at a given height; an admin signs `ROOT:{height}:{root_hex}`
// to authenticate it.

use blake2::{
    Blake2b, Digest,
    digest::consts::U32,
};

use crate::registry::Registration;

pub type Hash = [u8; 32];
type Blake2b256 = Blake2b<U32>;

const LEAF_TAG:     &[u8] = b"ZNSv1:LEAF\x00";
const INTERNAL_TAG: &[u8] = b"ZNSv1:NODE\x00";

/// Hash one registration into a 32-byte leaf.
///
/// Fields are separated by `\x00` so no field boundary can collide with a
/// legitimate value (names and UAs are alphanumeric, nonces are decimal,
/// actions are uppercase ASCII).
pub fn hash_leaf(reg: &Registration) -> Hash {
    let mut h = Blake2b256::new();
    h.update(LEAF_TAG);
    h.update(reg.name.as_bytes());
    h.update(b"\x00");
    h.update(reg.address.as_bytes());
    h.update(b"\x00");
    h.update(reg.nonce.to_be_bytes());
    h.update(reg.last_action.as_bytes());
    h.update(b"\x00");
    h.finalize().into()
}

fn hash_internal(left: &Hash, right: &Hash) -> Hash {
    let mut h = Blake2b256::new();
    h.update(INTERNAL_TAG);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Compute the Merkle root for a slice of leaf hashes. Empty input → all-zero
/// root (deterministic sentinel for an empty registry).
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .chunks(2)
            .map(|p| hash_internal(&p[0], &p[1]))
            .collect();
    }
    level[0]
}

/// Generate a sibling path for `index` against the same leaf slice used to
/// compute the root. Returns siblings bottom-up.
pub fn merkle_path(leaves: &[Hash], index: usize) -> Vec<Hash> {
    if leaves.is_empty() || index >= leaves.len() {
        return Vec::new();
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    let mut idx = index;
    let mut path = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        let sibling = if idx % 2 == 0 { level[idx + 1] } else { level[idx - 1] };
        path.push(sibling);
        idx /= 2;
        level = level
            .chunks(2)
            .map(|p| hash_internal(&p[0], &p[1]))
            .collect();
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(name: &str) -> Registration {
        Registration {
            name: name.into(),
            address: "u1example".into(),
            txid: "tx".into(),
            height: 1,
            nonce: 0,
            signature: None,
            last_action: "CLAIM".into(),
        }
    }

    #[test]
    fn root_is_deterministic() {
        let leaves: Vec<Hash> = ["a", "b", "c"].iter().map(|n| hash_leaf(&reg(n))).collect();
        assert_eq!(merkle_root(&leaves), merkle_root(&leaves));
    }

    #[test]
    fn path_verifies() {
        let names = ["a", "b", "c", "d", "e"];
        let leaves: Vec<Hash> = names.iter().map(|n| hash_leaf(&reg(n))).collect();
        let root = merkle_root(&leaves);
        for (i, _) in names.iter().enumerate() {
            let path = merkle_path(&leaves, i);
            let mut h = leaves[i];
            let mut idx = i;
            let mut len = leaves.len();
            for sib in &path {
                // mirror the padding logic so the index-bit walk matches what
                // root construction actually did at this level
                if len % 2 == 1 { len += 1; }
                h = if idx % 2 == 0 { hash_internal(&h, sib) } else { hash_internal(sib, &h) };
                idx /= 2;
                len /= 2;
            }
            assert_eq!(h, root, "path for index {i} failed");
        }
    }

    #[test]
    fn empty_root_is_zero() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }
}
