import 'package:test/test.dart';
import 'package:zcashname_sdk/zcashname_sdk.dart';

void main() {
  group('parseZip321Uri', () {
    test('parses address and amount', () {
      final r = parseZip321Uri('zcash:u1abc?amount=1.5&memo=abc123');
      expect(r.address, 'u1abc');
      expect(r.amount, '1.5');
    });

    test('decodes base64url memo', () {
      final r = parseZip321Uri('zcash:u1abc?memo=SGVsbG8');
      expect(r.memoDecoded, 'Hello');
    });

    test('returns empty strings for missing fields', () {
      final r = parseZip321Uri('zcash:u1abc');
      expect(r.amount, '');
      expect(r.memoRaw, '');
      expect(r.memoDecoded, '');
    });

    test('handles ZCASH: prefix case-insensitively', () {
      final r = parseZip321Uri('ZCASH:u1abc');
      expect(r.address, 'u1abc');
    });
  });

  group('buildZcashUri', () {
    test('returns base URI with no params when amount is null', () {
      expect(buildZcashUri('u1abc'), 'zcash:u1abc');
    });

    test('omits amount when 0', () {
      expect(buildZcashUri('u1abc', amountZats: 0), 'zcash:u1abc');
    });

    test('includes amount converted to ZEC', () {
      expect(buildZcashUri('u1abc', amountZats: 100000000),
          'zcash:u1abc?amount=1');
      expect(buildZcashUri('u1abc', amountZats: 10000001),
          'zcash:u1abc?amount=0.10000001');
      expect(buildZcashUri('u1abc', amountZats: 1000000),
          'zcash:u1abc?amount=0.01');
    });

    test('includes base64url-encoded memo', () {
      final uri = buildZcashUri('u1abc', memo: 'Hello');
      expect(uri.startsWith('zcash:u1abc?memo='), isTrue);
    });

    test('encodes memo without padding', () {
      // "Hello" base64-encoded with padding is "SGVsbG8=", without it's "SGVsbG8"
      final uri = buildZcashUri('u1abc', memo: 'Hello');
      final memoSegment = uri.split('memo=').last;
      expect(memoSegment.contains('='), isFalse);
    });
  });

  group('base64url helpers', () {
    test('toBase64Url/decodeBase64Url roundtrip', () {
      const input = 'Hello, ZNS world! 🦀';
      final encoded = toBase64Url(input);
      expect(encoded.contains('='), isFalse);
      expect(decodeBase64Url(encoded), input);
    });

    test('decodeBase64Url returns empty on bad input', () {
      expect(decodeBase64Url('@@@'), '');
    });
  });
}
