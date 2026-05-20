import 'package:test/test.dart';
import 'package:zcashname_sdk/zcashname_sdk.dart';

const _validTestnetUa =
    'utest100qlkeru5c3m5kfrwe2hsmcfzmusreaza2prdyelg2kd2tr2842nceq952vay3gpmgky09fgft4z57h4z2zqzz5rcwgd4q90u54ek5yyca4s6e6y2jja9sww27kzedzznjcupcu0svq2exvq995c0lhl5zm53g4ksnm2xuwt3snv4dgh';
const _validMainnetUa =
    'u1q8g0h9cn2x4eq8jd7k0d5y3zf6vhb5w4xj9tz3m5p6r2s1t0u7v8w9x0y1z';
const _validTestnetTaddr = 'tmqY61Gp3B7Pz3ev12NRFzWxJz1yB28Gfkfi';

void main() {
  group('isValidName', () {
    test('accepts valid names', () {
      expect(isValidName('alice'), isTrue);
      expect(isValidName('bob123'), isTrue);
      expect(isValidName('a'), isTrue);
      expect(isValidName('a' * 62), isTrue);
    });

    test('rejects invalid names', () {
      expect(isValidName(''), isFalse);
      expect(isValidName('Alice'), isFalse);
      expect(isValidName('my-name'), isFalse);
      expect(isValidName('a' * 63), isFalse);
    });
  });

  group('isValidUnifiedAddress', () {
    test('accepts testnet UA', () {
      expect(isValidUnifiedAddress(_validTestnetUa), isTrue);
    });

    test('accepts mainnet UA', () {
      expect(isValidUnifiedAddress(_validMainnetUa), isTrue);
    });

    test('rejects invalid addresses', () {
      expect(isValidUnifiedAddress(''), isFalse);
      expect(isValidUnifiedAddress('notanaddress'), isFalse);
      expect(isValidUnifiedAddress('zs1abc'), isFalse);
    });
  });

  group('isValidTransparentAddress', () {
    test('accepts testnet tm address', () {
      expect(isValidTransparentAddress(_validTestnetTaddr), isTrue);
    });

    test('rejects invalid addresses', () {
      expect(isValidTransparentAddress(''), isFalse);
      expect(isValidTransparentAddress('notanaddress'), isFalse);
      expect(isValidTransparentAddress('u1abc'), isFalse);
    });
  });
}
