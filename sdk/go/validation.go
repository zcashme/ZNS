package zns

import "regexp"

// namePattern matches valid ZNS names: 1-62 characters, lowercase ASCII
// letters and digits only. No hyphens, no underscores, no unicode.
var namePattern = regexp.MustCompile(`^[a-z0-9]{1,62}$`)

// IsValidName returns true if the given name is a valid ZNS name.
//
// A valid name:
//   - Is 1 to 62 characters long
//   - Contains only lowercase ASCII letters (a-z) and digits (0-9)
func IsValidName(name string) bool {
	return namePattern.MatchString(name)
}
