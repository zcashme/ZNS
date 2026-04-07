/// Pattern for valid ZNS names: 1-62 lowercase ASCII letters and digits.
/// No hyphens, no underscores, no unicode.
final _namePattern = RegExp(r'^[a-z0-9]{1,62}$');

/// Returns `true` if [name] is a valid ZNS name.
bool isValidName(String name) {
  return _namePattern.hasMatch(name);
}
