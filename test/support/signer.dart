// TEST-ONLY token signer, the counterpart of the Node.js tests'
// `makeKey`/`signJWT` helpers (which use node:crypto). The library never
// signs: this file lives under test/ and is not part of the package API.
// RSA keys come from test/vectors/signing_keys.json (test-only keys); EC and
// Ed25519 keys are generated per test run.
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256, sha512;
import 'package:proudauth_sdk/src/internal/base64url.dart';
import 'package:proudauth_sdk/src/internal/crypto/bigint.dart';
import 'package:proudauth_sdk/src/internal/crypto/ed25519.dart';
import 'package:proudauth_sdk/src/internal/crypto/p256.dart';

final Random _rng = Random.secure();

Uint8List randomBytes(int n) =>
    Uint8List.fromList(List<int>.generate(n, (_) => _rng.nextInt(256)));

String randomHex(int n) =>
    randomBytes(n).map((b) => b.toRadixString(16).padLeft(2, '0')).join();

String b64(Object v) =>
    encodeBase64Url(v is String ? utf8.encode(v) : v as List<int>);

BigInt _randomScalar(BigInt order) {
  for (;;) {
    final k = bigIntFromBytes(randomBytes(32));
    if (k > BigInt.zero && k < order) return k;
  }
}

/// A signing key for tests.
abstract class TestKey {
  TestKey(this.kid, this.alg);

  final String kid;
  final String alg;

  /// The public JWK (with kid, use and, unless disabled, alg).
  Map<String, Object?> get jwk;

  /// The private JWK members (for "private key in the key set" tests).
  Map<String, Object?> get privateJwk;

  Uint8List sign(List<int> data, {String? alg});

  /// The same key material under another kid/alg declaration.
  TestKey withKid(String kid, {String? alg, bool jwkAlg = true});
}

class EcTestKey extends TestKey {
  EcTestKey._(String kid, this.d, this.x, this.y, {this.jwkAlg = true})
      : super(kid, 'ES256');

  factory EcTestKey.generate({String? kid, bool jwkAlg = true}) {
    final d = _randomScalar(p256N);
    final q = p256MultiplyBase(d)!;
    return EcTestKey._(kid ?? 'es256-${randomHex(4)}', d, q.$1, q.$2,
        jwkAlg: jwkAlg);
  }

  final BigInt d;
  final BigInt x;
  final BigInt y;
  final bool jwkAlg;

  @override
  Map<String, Object?> get jwk => {
        'kty': 'EC',
        'crv': 'P-256',
        'x': encodeBase64Url(bigIntToBytes(x, 32)),
        'y': encodeBase64Url(bigIntToBytes(y, 32)),
        'kid': kid,
        'use': 'sig',
        if (jwkAlg) 'alg': alg,
      };

  @override
  Map<String, Object?> get privateJwk =>
      {...jwk, 'd': encodeBase64Url(bigIntToBytes(d, 32))};

  @override
  Uint8List sign(List<int> data, {String? alg}) {
    final n = p256N;
    final e = bigIntFromBytes(sha256.convert(data).bytes);
    for (;;) {
      final k = _randomScalar(n);
      final r = p256MultiplyBase(k)!.$1 % n;
      if (r == BigInt.zero) continue;
      final s = k.modInverse(n) * (e + r * d) % n;
      if (s == BigInt.zero) continue;
      return Uint8List.fromList(
          [...bigIntToBytes(r, 32), ...bigIntToBytes(s, 32)]);
    }
  }

  @override
  TestKey withKid(String kid, {String? alg, bool jwkAlg = true}) =>
      EcTestKey._(kid, d, x, y, jwkAlg: jwkAlg);
}

class Ed25519TestKey extends TestKey {
  Ed25519TestKey._(String kid, this._a, this._prefix, this.publicKey,
      {this.jwkAlg = true})
      : super(kid, 'EdDSA');

  factory Ed25519TestKey.fromSeed(List<int> seed, {String? kid}) {
    final h = sha512.convert(seed).bytes;
    final scalar = Uint8List.fromList(h.sublist(0, 32));
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    final a = bigIntFromBytesLE(scalar);
    final pub = ed25519Encode(ed25519MultiplyBase(a));
    return Ed25519TestKey._(kid ?? 'eddsa-${randomHex(4)}', a,
        Uint8List.fromList(h.sublist(32)), pub);
  }

  factory Ed25519TestKey.generate({String? kid}) =>
      Ed25519TestKey.fromSeed(randomBytes(32), kid: kid);

  final BigInt _a;
  final Uint8List _prefix;
  final Uint8List publicKey;
  final bool jwkAlg;

  @override
  Map<String, Object?> get jwk => {
        'kty': 'OKP',
        'crv': 'Ed25519',
        'x': encodeBase64Url(publicKey),
        'kid': kid,
        'use': 'sig',
        if (jwkAlg) 'alg': alg,
      };

  @override
  Map<String, Object?> get privateJwk =>
      {...jwk, 'd': encodeBase64Url(randomBytes(32))};

  @override
  Uint8List sign(List<int> data, {String? alg}) {
    final l = ed25519L;
    final r =
        bigIntFromBytesLE(sha512.convert([..._prefix, ...data]).bytes) % l;
    final rEnc = ed25519Encode(ed25519MultiplyBase(r));
    final k = bigIntFromBytesLE(
            sha512.convert([...rEnc, ...publicKey, ...data]).bytes) %
        l;
    final s = (r + k * _a) % l;
    return Uint8List.fromList([...rEnc, ...bigIntToBytesLE(s, 32)]);
  }

  @override
  TestKey withKid(String kid, {String? alg, bool jwkAlg = true}) =>
      Ed25519TestKey._(kid, _a, _prefix, publicKey, jwkAlg: jwkAlg);
}

class RsaTestKey extends TestKey {
  RsaTestKey._(super.kid, super.alg, this._c, {this.jwkAlg = true});

  /// Test-only RSA keys from test/vectors/signing_keys.json; [index] picks
  /// one of them (0, 1 or 2).
  factory RsaTestKey.fromPool(int index,
      {String alg = 'RS256', String? kid, bool jwkAlg = true}) {
    final c = _pool()[index];
    return RsaTestKey._(kid ?? '${alg.toLowerCase()}-${randomHex(4)}', alg, c,
        jwkAlg: jwkAlg);
  }

  final _RsaComponents _c;
  final bool jwkAlg;

  @override
  Map<String, Object?> get jwk => {
        'kty': 'RSA',
        'n': encodeBase64Url(bigIntToBytes(_c.n, _c.k)),
        'e': encodeBase64Url(bigIntToBytes(_c.e, 3)),
        'kid': kid,
        'use': 'sig',
        if (jwkAlg) 'alg': alg,
      };

  @override
  Map<String, Object?> get privateJwk => {..._c.raw, 'kid': kid};

  @override
  Uint8List sign(List<int> data, {String? alg}) {
    final a = alg ?? this.alg;
    final em = a == 'PS256' ? _pss(data) : _pkcs1(data);
    return bigIntToBytes(_c.privateOp(bigIntFromBytes(em)), _c.k);
  }

  Uint8List _pkcs1(List<int> data) {
    const prefix = [
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, //
      0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ];
    final t = [...prefix, ...sha256.convert(data).bytes];
    final ps = List<int>.filled(_c.k - t.length - 3, 0xff);
    return Uint8List.fromList([0, 1, ...ps, 0, ...t]);
  }

  Uint8List _pss(List<int> data) {
    final emBits = _c.n.bitLength - 1;
    final emLen = (emBits + 7) >> 3;
    final mHash = sha256.convert(data).bytes;
    final salt = randomBytes(32);
    final h =
        sha256.convert([...List<int>.filled(8, 0), ...mHash, ...salt]).bytes;
    final db = Uint8List(emLen - 33)
      ..[emLen - 33 - 33] = 0x01
      ..setRange(emLen - 33 - 32, emLen - 33, salt);
    final mask = _mgf1(h, db.length);
    for (var i = 0; i < db.length; i++) {
      db[i] ^= mask[i];
    }
    db[0] &= 0xff >> (8 * emLen - emBits);
    return Uint8List.fromList([...db, ...h, 0xbc]);
  }

  static List<int> _mgf1(List<int> seed, int len) {
    final out = <int>[];
    for (var c = 0; out.length < len; c++) {
      out.addAll(sha256.convert([
        ...seed,
        (c >> 24) & 0xff,
        (c >> 16) & 0xff,
        (c >> 8) & 0xff,
        c & 0xff
      ]).bytes);
    }
    return out.sublist(0, len);
  }

  @override
  TestKey withKid(String kid, {String? alg, bool jwkAlg = true}) =>
      RsaTestKey._(kid, alg ?? this.alg, _c, jwkAlg: jwkAlg);
}

class _RsaComponents {
  _RsaComponents(this.raw)
      : n = _b(raw['n']),
        e = _b(raw['e']),
        p = _b(raw['p']),
        q = _b(raw['q']),
        dp = _b(raw['dp']),
        dq = _b(raw['dq']),
        qi = _b(raw['qi']);

  static BigInt _b(Object? v) =>
      bigIntFromBytes(decodeBase64UrlLenient(v! as String));

  final Map<String, Object?> raw;
  final BigInt n, e, p, q, dp, dq, qi;

  int get k => (n.bitLength + 7) >> 3;

  // RSA private operation with the CRT.
  BigInt privateOp(BigInt m) {
    final m1 = m.modPow(dp, p);
    final m2 = m.modPow(dq, q);
    final h = qi * (m1 - m2) % p;
    return m2 + h * q;
  }
}

List<_RsaComponents>? _cache;

List<_RsaComponents> _pool() => _cache ??=
    ((jsonDecode(File('test/vectors/signing_keys.json').readAsStringSync())
            as Map<String, Object?>)['rsa']! as List<Object?>)
        .map((k) => _RsaComponents(k! as Map<String, Object?>))
        .toList();

/// A fresh key for [alg] (RSA keys come from a pool of three; pass [rsaIndex]
/// to pick one).
TestKey makeKey(String alg,
    {String? kid, bool jwkAlg = true, int rsaIndex = 0}) {
  switch (alg) {
    case 'ES256':
      return EcTestKey.generate(kid: kid, jwkAlg: jwkAlg);
    case 'EdDSA':
      final k = Ed25519TestKey.generate(kid: kid);
      return jwkAlg ? k : k.withKid(k.kid, jwkAlg: false);
    case 'RS256':
    case 'PS256':
      return RsaTestKey.fromPool(rsaIndex, alg: alg, kid: kid, jwkAlg: jwkAlg);
    default:
      throw ArgumentError('unsupported test alg $alg');
  }
}

/// Signs raw header/payload JSON text (lets tests craft duplicate members).
String signRaw(TestKey key, String headerJson, String payloadJson,
    [String? alg]) {
  final input = '${b64(headerJson)}.${b64(payloadJson)}';
  return '$input.${b64(key.sign(utf8.encode(input), alg: alg))}';
}

/// Signs a JWT; null values in [header] or [payload] remove that member
/// (the Node tests' `undefined`).
String signJwt(TestKey key, Map<String, Object?> payload,
    [Map<String, Object?> header = const {}]) {
  final h = <String, Object?>{
    'alg': key.alg,
    'kid': key.kid,
    'typ': 'at+jwt',
    ...header
  }..removeWhere((_, v) => v == null);
  final p = Map<String, Object?>.of(payload)..removeWhere((_, v) => v == null);
  return signRaw(key, jsonEncode(h), jsonEncode(p), h['alg'] as String?);
}
