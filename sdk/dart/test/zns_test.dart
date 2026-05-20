import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:zcashname_sdk/zcashname_sdk.dart';

const _ua =
    'utest100qlkeru5c3m5kfrwe2hsmcfzmusreaza2prdyelg2kd2tr2842nceq952vay3gpmgky09fgft4z57h4z2zqzz5rcwgd4q90u54ek5yyca4s6e6y2jja9sww27kzedzznjcupcu0svq2exvq995c0lhl5zm53g4ksnm2xuwt3snv4dgh';
const _taddr = 'tmqY61Gp3B7Pz3ev12NRFzWxJz1yB28Gfkfi';

void main() {
  group('constructor', () {
    test('defaults to testnet', () {
      final z = ZNS();
      expect(z.network, Network.testnet);
      expect(z.url, networks[Network.testnet]!.url);
    });

    test('accepts network option', () {
      final z = ZNS(network: Network.mainnet);
      expect(z.network, Network.mainnet);
      expect(z.url, networks[Network.mainnet]!.url);
    });

    test('accepts custom url', () {
      final custom = Uri.parse('https://custom.example.com');
      final z = ZNS(url: custom);
      expect(z.url, custom);
    });

    test('registryAddress matches network', () {
      final z = ZNS(network: Network.mainnet);
      expect(z.registryAddress, networks[Network.mainnet]!.registryAddress);
    });
  });

  group('claimCost', () {
    test('returns correct tier per name length', () {
      final z = ZNS();
      final p = Pricing(nonce: 0, height: 0, tiers: [100, 200, 300, 500, 1000]);
      expect(z.claimCost(1, p), 100);
      expect(z.claimCost(2, p), 200);
      expect(z.claimCost(3, p), 300);
      expect(z.claimCost(4, p), 500);
      expect(z.claimCost(62, p), 1000);
    });

    test('clamps to max tier for long names', () {
      final z = ZNS();
      final p = Pricing(nonce: 0, height: 0, tiers: [100, 200, 300]);
      expect(z.claimCost(100, p), 300);
    });

    test('returns null for empty tiers', () {
      final z = ZNS();
      expect(z.claimCost(5, Pricing(nonce: 0, height: 0, tiers: [])), isNull);
    });
  });

  group('listCommissionFor', () {
    test('returns 10% of minimum tier', () {
      final z = ZNS();
      final p = Pricing(nonce: 0, height: 0, tiers: [100, 200, 300]);
      expect(z.listCommissionFor(p), 10);
    });

    test('returns null for empty tiers', () {
      final z = ZNS();
      expect(
          z.listCommissionFor(Pricing(nonce: 0, height: 0, tiers: [])), isNull);
    });
  });

  group('prepareClaim', () {
    test('builds valid claim payload', () {
      final z = ZNS();
      final c = z.prepareClaim('alice', _ua, 1000);
      expect(c.payload, 'CLAIM:alice:$_ua');
      expect(c.name, 'alice');
      expect(c.address, _ua);
      expect(c.cost, 1000);
    });

    test('complete() builds memo without userPubkey', () {
      final z = ZNS();
      final c = z.prepareClaim('alice', _ua, 1000);
      final result = c.complete('SIGB64');
      expect(result.memo, 'ZNS:CLAIM:alice:$_ua:SIGB64');
      expect(result.memo.contains(':null'), isFalse);
      expect(result.uri.startsWith('zcash:'), isTrue);
      expect(result.uri.contains('amount='), isTrue);
    });

    test('complete() builds memo with userPubkey', () {
      final z = ZNS();
      final c = z.prepareClaim('alice', _ua, 1000);
      final result = c.complete('SIGB64', 'PKB64');
      expect(result.memo, endsWith(':SIGB64:PKB64'));
    });

    test('throws on invalid name', () {
      final z = ZNS();
      expect(() => z.prepareClaim('ALICE', _ua, 1000),
          throwsA(isA<InvalidNameException>()));
    });

    test('throws on invalid address', () {
      final z = ZNS();
      expect(() => z.prepareClaim('alice', 'notvalid', 1000),
          throwsA(isA<InvalidAddressException>()));
    });
  });

  group('prepareList', () {
    test('builds valid list payload', () {
      final z = ZNS();
      final l = z.prepareList('alice', 100000000, _taddr, 1);
      expect(l.payload, 'LIST:alice:100000000:$_taddr:1');
    });

    test('complete() URI uses list commission amount', () {
      final z = ZNS();
      final l = z.prepareList('alice', 100000000, _taddr, 1);
      final r = l.complete('SIG');
      // listCommission = 1_000_000 zats = 0.01 ZEC
      expect(r.uri, contains('amount=0.01'));
    });

    test('throws on invalid transparent address', () {
      final z = ZNS();
      expect(() => z.prepareList('alice', 100000000, 'notvalid', 1),
          throwsA(isA<InvalidAddressException>()));
    });
  });

  group('prepareUpdate', () {
    test('builds valid update payload', () {
      final z = ZNS();
      final u = z.prepareUpdate('alice', _ua, 2);
      expect(u.payload, 'UPDATE:alice:$_ua:2');
    });

    test('throws on invalid address', () {
      final z = ZNS();
      expect(() => z.prepareUpdate('alice', 'notvalid', 2),
          throwsA(isA<InvalidAddressException>()));
    });
  });

  group('prepareBuy', () {
    test('builds valid buy payload + URI uses BUY commission', () {
      final z = ZNS();
      final b = z.prepareBuy('alice', _ua, 50000000);
      expect(b.payload, 'BUY:alice:$_ua');
      final r = b.complete('SIG');
      expect(r.uri, contains('amount=0.0001'));
      expect(r.memo, contains(':50000000:SIG'));
    });
  });

  group('prepareRelease / prepareDelist', () {
    test('release payload', () {
      expect(ZNS().prepareRelease('alice', 4).payload, 'RELEASE:alice:4');
    });
    test('delist payload', () {
      expect(ZNS().prepareDelist('alice', 5).payload, 'DELIST:alice:5');
    });
  });

  group('prepareSetPrice', () {
    test('builds payload + memo', () {
      final p = ZNS().prepareSetPrice([100, 200, 300], 1);
      expect(p.payload, 'SETPRICE:3:100:200:300:1');
      final r = p.complete('SIG');
      expect(r.memo, 'ZNS:SETPRICE:3:100:200:300:1:SIG');
    });

    test('userPubkey is ignored (admin-only)', () {
      final p = ZNS().prepareSetPrice([100], 1);
      final r = p.complete('SIG', 'PKB64');
      expect(r.memo, 'ZNS:SETPRICE:1:100:1:SIG');
    });
  });

  group('PreparedAction (sealed)', () {
    test('exhaustive switch yields action enum', () {
      final z = ZNS();
      final actions = <PreparedAction>[
        z.prepareClaim('alice', _ua, 100),
        z.prepareList('alice', 100, _taddr, 1),
        z.prepareDelist('alice', 1),
        z.prepareUpdate('alice', _ua, 1),
        z.prepareBuy('alice', _ua, 100),
        z.prepareRelease('alice', 1),
        z.prepareSetPrice([100], 1),
      ];
      final seen = <ZnsAction>{};
      for (final a in actions) {
        seen.add(switch (a) {
          PreparedClaim() => ZnsAction.claim,
          PreparedList() => ZnsAction.list,
          PreparedDelist() => ZnsAction.delist,
          PreparedUpdate() => ZnsAction.update,
          PreparedBuy() => ZnsAction.buy,
          PreparedRelease() => ZnsAction.release,
          PreparedSetPrice() => ZnsAction.setprice,
        });
      }
      expect(seen, ZnsAction.values.toSet());
    });
  });

  group('ZnsAction enum', () {
    test('fromWire is case-insensitive', () {
      expect(ZnsAction.fromWire('CLAIM'), ZnsAction.claim);
      expect(ZnsAction.fromWire('claim'), ZnsAction.claim);
      expect(ZnsAction.fromWire('Setprice'), ZnsAction.setprice);
      expect(ZnsAction.fromWire('NOPE'), isNull);
    });

    test('isUserSignable excludes SETPRICE only', () {
      expect(ZnsAction.setprice.isUserSignable, isFalse);
      expect(ZnsAction.claim.isUserSignable, isTrue);
      expect(ZnsAction.list.isUserSignable, isTrue);
    });

    test('isOwnershipChanging excludes LIST and SETPRICE', () {
      expect(ZnsAction.list.isOwnershipChanging, isFalse);
      expect(ZnsAction.setprice.isOwnershipChanging, isFalse);
      expect(ZnsAction.claim.isOwnershipChanging, isTrue);
      expect(ZnsAction.delist.isOwnershipChanging, isTrue);
    });
  });

  group('verifySovereignSignature', () {
    test('verifies a real Ed25519 signature', () async {
      final algo = Ed25519();
      final pair = await algo.newKeyPair();
      final pubkey = await pair.extractPublicKey();

      const payload = 'CLAIM:alice:utest1';
      final sig = await algo.sign(utf8.encode(payload), keyPair: pair);
      final sigB64 = base64.encode(sig.bytes);
      final pkB64 = base64.encode(pubkey.bytes);

      final z = ZNS();
      expect(await z.verifySovereignSignature(payload, sigB64, pkB64), isTrue);
    });

    test('rejects tampered payload', () async {
      final algo = Ed25519();
      final pair = await algo.newKeyPair();
      final pubkey = await pair.extractPublicKey();

      const payload = 'CLAIM:alice:utest1';
      const tampered = 'CLAIM:bob:utest1';
      final sig = await algo.sign(utf8.encode(payload), keyPair: pair);
      final sigB64 = base64.encode(sig.bytes);
      final pkB64 = base64.encode(pubkey.bytes);

      final z = ZNS();
      expect(
          await z.verifySovereignSignature(tampered, sigB64, pkB64), isFalse);
    });

    test('returns false on malformed base64', () async {
      final z = ZNS();
      expect(await z.verifySovereignSignature('CLAIM:a:b', '!!!', '!!!'),
          isFalse);
    });

    test('returns false on wrong-length pubkey', () async {
      final z = ZNS();
      // 32-byte signature, 16-byte "pubkey" — both decodable but wrong length.
      final sig = base64.encode(List<int>.filled(64, 0));
      final pk = base64.encode(List<int>.filled(16, 0));
      expect(
          await z.verifySovereignSignature('CLAIM:a:b', sig, pk), isFalse);
    });
  });

  group('models', () {
    test('Registration.fromJson decodes snake_case', () {
      final reg = Registration.fromJson({
        'name': 'alice',
        'address': _ua,
        'txid': 'abc',
        'height': 100,
        'nonce': 1,
        'signature': 'SIG',
        'last_action': 'CLAIM',
        'pubkey': null,
      });
      expect(reg.name, 'alice');
      expect(reg.lastAction, ZnsAction.claim);
      expect(reg.listing, isNull);
    });

    test('Registration.fromJson throws on non-ownership last_action', () {
      expect(
        () => Registration.fromJson({
          'name': 'alice',
          'address': _ua,
          'txid': 'abc',
          'height': 100,
          'nonce': 1,
          'signature': 'SIG',
          'last_action': 'LIST',
          'pubkey': null,
        }),
        throwsA(isA<FormatException>()),
      );
    });

    test('Registration value equality', () {
      final a = Registration(
        name: 'alice',
        address: _ua,
        txid: 'abc',
        height: 100,
        nonce: 1,
        lastAction: ZnsAction.claim,
      );
      final b = Registration(
        name: 'alice',
        address: _ua,
        txid: 'abc',
        height: 100,
        nonce: 1,
        lastAction: ZnsAction.claim,
      );
      expect(a, equals(b));
      expect(a.hashCode, b.hashCode);
    });

    test('Listing.fromJson handles pending_buy', () {
      final l = Listing.fromJson({
        'name': 'alice',
        'price': 10,
        'pay_taddr': _taddr,
        'nonce': 1,
        'txid': 'abc',
        'height': 100,
        'signature': 'SIG',
        'pubkey': null,
        'pending_buy': {
          'buyer': 'utest1xxx',
          'price': 10,
          'claim_height': 101,
          'expires_at': 200,
          'txid': 'def',
        },
      });
      expect(l.payTaddr, _taddr);
      expect(l.pendingBuy?.claimHeight, 101);
      expect(l.pendingBuy?.expiresAt, 200);
    });
  });
}
