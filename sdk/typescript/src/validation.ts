/**
 * ZNS name validation. Names are 1–62 characters of lowercase ASCII letters
 * and digits only. No hyphens, no underscores, no dots, no unicode.
 *
 * Mirrors the indexer's `validate_name` in `src/memo.rs`.
 */
export function isValidName(name: string): boolean {
  return /^[a-z0-9]{1,62}$/.test(name);
}
