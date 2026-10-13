/// Minimal, strict JWS compact-serialization support for the four
/// asymmetric algorithms ProudAuth issues (RS256, PS256, ES256,
/// EdDSA/Ed25519), a port of the Node.js SDK's `internal/jws.ts`. There is
/// no "none", no HMAC and no algorithm fallback (TOK-005).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;

import 'base64url.dart';
import 'crypto/bigint.dart';
import 'crypto/ed25519.dart';
import 'crypto/p256.dart';
import 'crypto/rsa.dart';
import 'json.dart';

/// The algorithms the SDK verifies.
const List<String> supportedAlgorithms = ['RS256', 'PS256', 'ES256', 'EdDSA'];

final RegExp _hmac = RegExp(r'^hs', caseSensitive: false);

/// Validates an algorithm allowlist; "none" and symmetric algorithms are
/// always refused. Throws [ArgumentError].
Set<String> resolveAlgorithms(List<String>? algorithms, String prefix) {
  final list = algorithms == null || algorithms.isEmpty
      ? supportedAlgorithms
      : algorithms;
  for (final a in list) {
    if (a.toLowerCase() == 'none' || _hmac.hasMatch(a)) {
      throw ArgumentError(
          '$prefix: algorithm $a is not allowed (no symmetric or unsigned tokens)');
    }
    if (!supportedAlgorithms.contains(a)) {
      throw ArgumentError(
          '$prefix: algorithm $a is not supported (supported: ${supportedAlgorithms.join(', ')})');
    }
  }
  return Set.unmodifiable(list);
}

/// Why a compact JWS could not be parsed.
enum JwsFailure { malformed, duplicate }

/// A parsing failure; never contains token material.
final class JwsParseException implements Exception {
  const JwsParseException(this.reason);
  final JwsFailure reason;
  @override
  String toString() => reason == JwsFailure.duplicate
      ? 'duplicate JSON member'
      : 'malformed JWS';
}

/// A parsed, not yet verified, compact JWS.
final class ParsedJws {
  ParsedJws(this.header, this.payload, this.signingInput, this.signature);

  final Map<String, Object?> header;
  final Map<String, Object?> payload;
  final Uint8List signingInput;
  final Uint8List signature;
}

Map<String, Object?> _segment(Uint8List bytes) {
  final String text;
  try {
    text = decodeUtf8Strict(bytes);
  } on FormatException {
    throw const JwsParseException(JwsFailure.malformed);
  }
  final Object? value;
  try {
    value = parseStrictJson(text);
  } on StrictJsonException catch (e) {
    throw JwsParseException(e.reason == StrictJsonFailure.duplicate
        ? JwsFailure.duplicate
        : JwsFailure.malformed);
  }
  if (value is! Map<String, Object?>) {
    throw const JwsParseException(JwsFailure.malformed);
  }
  return value;
}

/// Parses a compact JWS: exactly three canonical base64url segments; header
/// and payload must be JSON objects without duplicate members or trailing
/// data. Nothing here is trusted until the signature has been verified.
ParsedJws parseCompactJws(String raw) {
  final parts = raw.split('.');
  if (parts.length != 3) throw const JwsParseException(JwsFailure.malformed);
  final Uint8List hb, pb, sig;
  try {
    hb = decodeBase64UrlStrict(parts[0]);
    pb = decodeBase64UrlStrict(parts[1]);
    sig = decodeBase64UrlStrict(parts[2]);
  } on FormatException {
    throw const JwsParseException(JwsFailure.malformed);
  }
  final header = _segment(hb);
  final payload = _segment(pb);
  return ParsedJws(
    header,
    payload,
    Uint8List.fromList(ascii.encode('${parts[0]}.${parts[1]}')),
    sig,
  );
}

/// A public verification key from a JWK.
sealed class PublicKeyMaterial {
  const PublicKeyMaterial();
}

/// An RSA key (RS256, PS256).
final class RsaKeyMaterial extends PublicKeyMaterial {
  const RsaKeyMaterial(this.key);
  final RsaPublicKey key;
}

/// A P-256 key (ES256), validated to be on the curve.
final class EcKeyMaterial extends PublicKeyMaterial {
  const EcKeyMaterial(this.x, this.y);
  final BigInt x;
  final BigInt y;
}

/// An Ed25519 key (EdDSA). [point] is null when the 32 bytes are not a
/// canonical curve point: the key is kept (as OpenSSL does) but every
/// signature fails.
final class EdKeyMaterial extends PublicKeyMaterial {
  const EdKeyMaterial(this.bytes, this.point);
  final Uint8List bytes;
  final EdwardsPoint? point;
}

/// One usable verification key of a key set.
final class VerificationKey {
  const VerificationKey(this.kid, this.alg, this.material);

  final String kid;

  /// The JWK "alg" member, when the key set declares one.
  final String? alg;
  final PublicKeyMaterial material;
}

const List<String> _privateMembers = [
  'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', //
];

/// Smallest and largest accepted RSA moduli.
const int minRsaBits = 2048;
const int maxRsaBits = 16384;

/// Imports one public verification key. Keys without a kid, keys not meant
/// for signatures, private or symmetric keys, unsupported curves, points off
/// the curve and RSA keys shorter than 2048 bits are skipped (null) rather
/// than trusted.
VerificationKey? importJwk(Object? jwk) {
  if (jwk is! Map<String, Object?>) return null;
  final kid = jwk['kid'];
  if (kid is! String || kid.isEmpty) return null;
  if (jwk.containsKey('use') && jwk['use'] != 'sig') return null;
  if (jwk.containsKey('key_ops')) {
    final ops = jwk['key_ops'];
    if (ops is! List<Object?> || !ops.contains('verify')) return null;
  }
  final alg = jwk['alg'];
  if (jwk.containsKey('alg') && alg is! String) return null;
  for (final m in _privateMembers) {
    if (jwk.containsKey(m)) return null;
  }
  final PublicKeyMaterial? material;
  try {
    material = switch (jwk['kty']) {
      'EC' => _importEc(jwk),
      'OKP' => _importOkp(jwk),
      'RSA' => _importRsa(jwk),
      _ => null,
    };
  } on FormatException {
    return null;
  }
  if (material == null) return null;
  return VerificationKey(kid, alg as String?, material);
}

Uint8List? _member(Map<String, Object?> jwk, String name) {
  final v = jwk[name];
  if (v is! String) return null;
  return decodeBase64UrlLenient(v);
}

PublicKeyMaterial? _importEc(Map<String, Object?> jwk) {
  if (jwk['crv'] != 'P-256') return null;
  final x = _member(jwk, 'x');
  final y = _member(jwk, 'y');
  if (x == null || y == null || x.length != 32 || y.length != 32) return null;
  final bx = bigIntFromBytes(x);
  final by = bigIntFromBytes(y);
  if (!p256IsOnCurve(bx, by)) return null;
  return EcKeyMaterial(bx, by);
}

PublicKeyMaterial? _importOkp(Map<String, Object?> jwk) {
  if (jwk['crv'] != 'Ed25519') return null;
  final x = _member(jwk, 'x');
  if (x == null || x.length != 32) return null;
  return EdKeyMaterial(x, ed25519Decode(x));
}

PublicKeyMaterial? _importRsa(Map<String, Object?> jwk) {
  final n = _member(jwk, 'n');
  final e = _member(jwk, 'e');
  if (n == null || e == null || n.isEmpty || e.isEmpty) return null;
  final bn = bigIntFromBytes(n);
  if (bn.bitLength < minRsaBits || bn.bitLength > maxRsaBits) return null;
  final key = RsaPublicKey.fromComponents(bn, bigIntFromBytes(e));
  return key == null ? null : RsaKeyMaterial(key);
}

/// Verifies a JWS signature. The key type must match the algorithm, so an
/// RSA key can never verify an ES256 token and vice versa.
bool verifySignature(
  String alg,
  PublicKeyMaterial key,
  Uint8List data,
  Uint8List signature,
) {
  try {
    switch (alg) {
      case 'RS256':
        return key is RsaKeyMaterial &&
            rsaVerifyPkcs1v15Sha256(key.key, data, signature);
      case 'PS256':
        return key is RsaKeyMaterial &&
            rsaVerifyPssSha256(key.key, data, signature);
      case 'ES256':
        return key is EcKeyMaterial &&
            signature.length == 64 &&
            p256Verify(key.x, key.y, sha256.convert(data).bytes, signature);
      case 'EdDSA':
        final point = key is EdKeyMaterial ? key.point : null;
        return point != null &&
            ed25519VerifyDecoded(
                point, (key as EdKeyMaterial).bytes, data, signature);
      default:
        return false;
    }
  } catch (_) {
    return false;
  }
}
