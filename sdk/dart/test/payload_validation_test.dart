import 'package:test/test.dart';
import 'package:zcashname_sdk/zcashname_sdk.dart';

const _ua =
    'utest100qlkeru5c3m5kfrwe2hsmcfzmusreaza2prdyelg2kd2tr2842nceq952vay3gpmgky09fgft4z57h4z2zqzz5rcwgd4q90u54ek5yyca4s6e6y2jja9sww27kzedzznjcupcu0svq2exvq995c0lhl5zm53g4ksnm2xuwt3snv4dgh';
const _taddr = 'tmqY61Gp3B7Pz3ev12NRFzWxJz1yB28Gfkfi';

void main() {
  group('CLAIM', () {
    test('accepts valid payload', () {
      final r = validatePayload('CLAIM:alice:$_ua');
      expect(r.valid, isTrue);
      expect(r.action, 'CLAIM');
      expect(r.level, PayloadValidationLevel.valid);
    });

    test('rejects invalid name', () {
      final r = validatePayload('CLAIM:UPPER:$_ua');
      expect(r.valid, isFalse);
      expect(r.message, contains('lowercase'));
    });

    test('rejects invalid UA', () {
      final r = validatePayload('CLAIM:alice:zs1notvalid');
      expect(r.valid, isFalse);
      expect(r.message, contains('unified address'));
    });

    test('rejects wrong part count', () {
      final r = validatePayload('CLAIM:alice:$_ua:extra');
      expect(r.valid, isFalse);
      expect(r.message, contains('Expected CLAIM'));
    });
  });

  test('BUY accepts valid payload', () {
    final r = validatePayload('BUY:alice:$_ua');
    expect(r.valid, isTrue);
    expect(r.action, 'BUY');
  });

  group('UPDATE', () {
    test('accepts valid payload', () {
      final r = validatePayload('UPDATE:alice:$_ua:1');
      expect(r.valid, isTrue);
    });

    test('rejects non-numeric nonce', () {
      final r = validatePayload('UPDATE:alice:$_ua:abc');
      expect(r.valid, isFalse);
      expect(r.message, contains('whole number'));
    });
  });

  group('LIST', () {
    test('accepts valid payload with t-addr', () {
      final r = validatePayload('LIST:alice:100000000:$_taddr:1');
      expect(r.valid, isTrue);
    });

    test('rejects zero price', () {
      final r = validatePayload('LIST:alice:0:$_taddr:1');
      expect(r.valid, isFalse);
      expect(r.message, contains('positive whole number'));
    });

    test('rejects negative price', () {
      final r = validatePayload('LIST:alice:-1:$_taddr:1');
      expect(r.valid, isFalse);
    });
  });

  test('DELIST accepts valid payload', () {
    final r = validatePayload('DELIST:alice:2');
    expect(r.valid, isTrue);
  });

  test('RELEASE accepts valid payload', () {
    final r = validatePayload('RELEASE:alice:3');
    expect(r.valid, isTrue);
  });

  group('case insensitivity', () {
    test('lowercase action', () {
      final r = validatePayload('claim:alice:$_ua');
      expect(r.valid, isTrue);
      expect(r.action, 'CLAIM');
    });

    test('mixed case action', () {
      final r = validatePayload('ClAiM:alice:$_ua');
      expect(r.valid, isTrue);
      expect(r.action, 'CLAIM');
    });
  });

  group('error cases', () {
    test('empty payload', () {
      final r = validatePayload('');
      expect(r.valid, isFalse);
      expect(r.level, PayloadValidationLevel.invalid);
    });

    test('unknown action', () {
      final r = validatePayload('FOO:bar:baz');
      expect(r.valid, isFalse);
      expect(r.level, PayloadValidationLevel.unrecognized);
    });

    test('missing colon', () {
      final r = validatePayload('CLAIM');
      expect(r.valid, isFalse);
      expect(r.message, contains('Missing colon'));
    });
  });
}
