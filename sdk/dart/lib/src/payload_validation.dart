import 'actions.dart';
import 'models.dart';
import 'validators.dart';

/// User-signable ZNS actions. Backed by [ZnsAction].
List<String> get znsActions =>
    ZnsAction.values.where((a) => a.isUserSignable).map((a) => a.wire).toList();

enum _Check { name, ua, price, nonce, payTaddr }

class _Rule {
  final String format;
  final List<_Check> checks;
  const _Rule(this.format, this.checks);
}

const _rules = <ZnsAction, _Rule>{
  ZnsAction.claim: _Rule('CLAIM:<name>:<ua>', [_Check.name, _Check.ua]),
  ZnsAction.buy: _Rule('BUY:<name>:<ua>', [_Check.name, _Check.ua]),
  ZnsAction.update: _Rule('UPDATE:<name>:<ua>:<nonce>',
      [_Check.name, _Check.ua, _Check.nonce]),
  ZnsAction.list: _Rule('LIST:<name>:<price>:<pay_taddr>:<nonce>',
      [_Check.name, _Check.price, _Check.payTaddr, _Check.nonce]),
  ZnsAction.delist: _Rule('DELIST:<name>:<nonce>', [_Check.name, _Check.nonce]),
  ZnsAction.release:
      _Rule('RELEASE:<name>:<nonce>', [_Check.name, _Check.nonce]),
};

bool _isWholeNumber(String s) {
  if (s == '0') return true;
  if (s.isEmpty || s.startsWith('0')) return false;
  for (final c in s.codeUnits) {
    if (c < 0x30 || c > 0x39) return false;
  }
  return true;
}

String? _validateField(String value, _Check check) {
  switch (check) {
    case _Check.name:
      return isValidName(value)
          ? null
          : 'Invalid name. Use lowercase a-z and 0-9, 1 to 62 chars.';
    case _Check.ua:
      return isValidUnifiedAddress(value)
          ? null
          : 'Invalid unified address: "$value".';
    case _Check.price:
      if (!_isWholeNumber(value)) {
        return 'Price must be a positive whole number in zats.';
      }
      final n = int.tryParse(value);
      if (n == null || n <= 0) {
        return 'Price must be a positive whole number in zats.';
      }
      return null;
    case _Check.nonce:
      return _isWholeNumber(value) ? null : 'Nonce must be a whole number.';
    case _Check.payTaddr:
      return isValidTransparentAddress(value)
          ? null
          : 'Invalid transparent address: "$value".';
  }
}

PayloadValidationResult _result(
        PayloadValidationLevel level, String action, String message) =>
    PayloadValidationResult(
      valid: level == PayloadValidationLevel.valid,
      action: action,
      message: message,
      level: level,
    );

/// Validate a signing payload against the ZNS memo format spec.
///
/// Mirrors the Rust indexer's `parse_memo` + `signing_payload`. Does NOT
/// verify the signature, and does NOT check the name against the chain.
PayloadValidationResult validatePayload(String payload) {
  final raw = payload.trim();
  if (raw.isEmpty) {
    return _result(PayloadValidationLevel.invalid, '', 'Empty payload.');
  }

  final colonIdx = raw.indexOf(':');
  if (colonIdx == -1) {
    return _result(
      PayloadValidationLevel.invalid,
      raw.toUpperCase(),
      'Missing colon separator. Expected format: ACTION:field1:field2:...',
    );
  }

  final actionStr = raw.substring(0, colonIdx).toUpperCase();
  final rest = raw.substring(colonIdx + 1);
  final parts = rest.split(':');

  final action = ZnsAction.fromWire(actionStr);
  if (action == null || !action.isUserSignable) {
    final valid =
        ZnsAction.values.where((a) => a.isUserSignable).map((a) => a.wire);
    return _result(
      PayloadValidationLevel.unrecognized,
      actionStr,
      'Unrecognized action "$actionStr". Valid actions: ${valid.join(", ")}.',
    );
  }

  final rule = _rules[action]!;
  if (parts.length != rule.checks.length) {
    return _result(
      PayloadValidationLevel.invalid,
      actionStr,
      'Expected ${rule.format}.',
    );
  }
  for (var i = 0; i < rule.checks.length; i++) {
    final err = _validateField(parts[i], rule.checks[i]);
    if (err != null) {
      return _result(PayloadValidationLevel.invalid, actionStr, err);
    }
  }
  return _result(
      PayloadValidationLevel.valid, actionStr, 'Valid $actionStr payload.');
}
