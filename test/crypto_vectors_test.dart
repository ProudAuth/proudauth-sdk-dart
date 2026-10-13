// Independent signature vectors (test/vectors/*.json): every expectation was
// decided by Go's standard library, never by this package. See
// test/vectors/README.md.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:proudauth_sdk/src/internal/crypto/ed25519.dart';
import 'package:proudauth_sdk/src/internal/crypto/p256.dart';
import 'package:proudauth_sdk/src/internal/crypto/rsa.dart';
import 'package:proudauth_sdk/src/internal/jws.dart';
import 'package:test/test.dart';

import 'support/hex.dart';
import 'support/signer.dart';

Map<String, Object?> _load(String name) =>
    jsonDecode(File('test/vectors/$name').readAsStringSync())
        as Map<String, Object?>;

void _runVectorFile(String file, String alg) {
  final vf = _load(file);
  final keys = (vf['keys'] as Map<String, Object?>)
      .map((kid, jwk) => MapEntry(kid, importJwk(jwk)));
  final cases = (vf['cases'] as List<Object?>).cast<Map<String, Object?>>();

  test('$alg: imports every vector key', () {
    for (final e in keys.entries) {
      expect(e.value, isNotNull, reason: e.key);
      expect(e.value!.alg, alg, reason: e.key);
    }
  });

  test('$alg: ${cases.length} cases match the Go oracle', () {
    var valid = 0;
    for (final c in cases) {
      final key = keys[c['kid']]!;
      final ok = verifySignature(
        alg,
        key.material,
        hexDecode(c['msg']! as String),
        hexDecode(c['sig']! as String),
      );
      expect(ok, c['valid'], reason: '${c['name']}: ${c['why']}');
      if (ok) valid++;
    }
    expect(valid, greaterThan(0));
    expect(valid, lessThan(cases.length));
  });

  final invalid = (vf['invalid_keys'] as List<Object?>? ?? const [])
      .cast<Map<String, Object?>>();
  if (invalid.isNotEmpty) {
    test('$alg: skips ${invalid.length} unusable keys', () {
      for (final k in invalid) {
        expect(importJwk(k['jwk']), isNull,
            reason: '${k['name']}: ${k['why']}');
      }
    });
  }
}

void main() {
  group('RS256 vectors', () => _runVectorFile('rs256.json', 'RS256'));
  group('PS256 vectors', () => _runVectorFile('ps256.json', 'PS256'));
  group('ES256 vectors', () => _runVectorFile('es256.json', 'ES256'));
  group('EdDSA vectors', () => _runVectorFile('ed25519.json', 'EdDSA'));

  group('algorithm and key-type binding', () {
    test('a key verifies only its own algorithm family', () {
      final rs = _load('rs256.json');
      final rsKid = (rs['keys'] as Map<String, Object?>).keys.first;
      final rsKey = importJwk((rs['keys'] as Map<String, Object?>)[rsKid])!;
      final valid = (rs['cases'] as List<Object?>)
          .cast<Map<String, Object?>>()
          .firstWhere((c) => c['kid'] == rsKid && c['valid'] == true);
      final msg = hexDecode(valid['msg']! as String);
      final sig = hexDecode(valid['sig']! as String);
      expect(verifySignature('RS256', rsKey.material, msg, sig), isTrue);
      for (final alg in ['PS256', 'ES256', 'EdDSA', 'HS256', 'none', '']) {
        expect(verifySignature(alg, rsKey.material, msg, sig), isFalse,
            reason: alg);
      }
    });
  });

  group('RFC 8032 section 7.1', () {
    // The test signer reproduces the RFC signatures from the RFC seeds: this
    // checks the point arithmetic shared with verification against the RFC.
    test('the test signer reproduces tests 1 to 3', () {
      final vf = _load('ed25519.json');
      final keys = vf['keys'] as Map<String, Object?>;
      for (final c in (vf['cases'] as List<Object?>)
          .cast<Map<String, Object?>>()
          .where((c) => (c['name'] as String).startsWith('rfc8032_'))) {
        final jwk = keys[c['kid']] as Map<String, Object?>;
        final signer =
            Ed25519TestKey.fromSeed(hexDecode(jwk['seed']! as String));
        final msg = hexDecode(c['msg']! as String);
        expect(hexEncode(signer.sign(msg)), c['sig'],
            reason: c['name'] as String);
        expect(signer.jwk['x'], jwk['x']);
      }
    });

    test('rejects S + L and S >= L (canonical-S check)', () {
      final signer = Ed25519TestKey.generate();
      final msg = utf8.encode('malleability');
      final sig = signer.sign(msg);
      expect(ed25519Verify(signer.publicKey, msg, sig), isTrue);
      final s = _leToBig(sig.sublist(32));
      final malleated = Uint8List.fromList(
          [...sig.sublist(0, 32), ..._bigToLe(s + ed25519L, 32)]);
      expect(ed25519Verify(signer.publicKey, msg, malleated), isFalse);
      final atL = Uint8List.fromList(
          [...sig.sublist(0, 32), ..._bigToLe(ed25519L, 32)]);
      expect(ed25519Verify(signer.publicKey, msg, atL), isFalse);
    });

    test('point decoding rejects non-canonical and off-curve encodings', () {
      final p = (BigInt.one << 255) - BigInt.from(19);
      expect(ed25519Decode(_bigToLe(p, 32)), isNull, reason: 'y = p');
      expect(ed25519Decode(_bigToLe(p + BigInt.one, 32)), isNull,
          reason: 'y = p + 1 (non-canonical 1)');
      expect(ed25519Decode(_bigToLe(BigInt.two, 32)), isNull,
          reason: 'not on the curve');
      // y = 1 is the identity (x = 0); x = 0 with the sign bit set is invalid.
      final negZero = _bigToLe(BigInt.one, 32)..[31] |= 0x80;
      expect(ed25519Decode(_bigToLe(BigInt.one, 32)), isNotNull);
      expect(ed25519Decode(negZero), isNull);
      expect(ed25519Decode(Uint8List(31)), isNull);
    });
  });

  group('P-256', () {
    test('the generator is on the curve and has order n', () {
      final g = p256MultiplyBase(BigInt.one)!;
      expect(p256IsOnCurve(g.$1, g.$2), isTrue);
      expect(p256MultiplyBase(p256N), isNull);
      expect(p256MultiplyBase(p256N - BigInt.one)!.$1, g.$1);
    });

    test('test-signer signatures verify; high-S verifies; off-curve fails', () {
      final key = EcTestKey.generate();
      final msg = utf8.encode('p256 round trip');
      final sig = key.sign(msg);
      final digest = sha256.convert(msg).bytes;
      expect(p256Verify(key.x, key.y, digest, sig), isTrue);
      final r = sig.sublist(0, 32);
      final s = _beToBig(sig.sublist(32));
      final highS = Uint8List.fromList([...r, ..._bigToBe(p256N - s, 32)]);
      expect(p256Verify(key.x, key.y, digest, highS), isTrue);
      expect(p256Verify(key.x, key.y + BigInt.one, digest, sig), isFalse);
      expect(p256Verify(key.x, key.y, digest, sig.sublist(1)), isFalse);
    });
  });

  group('RSA', () {
    test('rejects e = 1, even moduli and e >= n', () {
      final n = BigInt.parse('c' * 512, radix: 16) + BigInt.one; // odd
      expect(RsaPublicKey.fromComponents(n, BigInt.one), isNull);
      expect(RsaPublicKey.fromComponents(n, BigInt.two), isNull);
      expect(RsaPublicKey.fromComponents(n, n), isNull);
      expect(RsaPublicKey.fromComponents(n - BigInt.one, BigInt.from(65537)),
          isNull);
      expect(RsaPublicKey.fromComponents(n, BigInt.from(65537)), isNotNull);
    });
  });
}

BigInt _leToBig(List<int> b) => _beToBig(b.reversed.toList());
BigInt _beToBig(List<int> b) =>
    b.isEmpty ? BigInt.zero : BigInt.parse(hexEncode(b), radix: 16);
Uint8List _bigToBe(BigInt v, int len) =>
    hexDecode(v.toRadixString(16).padLeft(len * 2, '0'));
Uint8List _bigToLe(BigInt v, int len) =>
    Uint8List.fromList(_bigToBe(v, len).reversed.toList());
