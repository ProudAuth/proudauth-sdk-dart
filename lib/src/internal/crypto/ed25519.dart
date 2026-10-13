/// Ed25519 signature verification (RFC 8032 §5.1.7) for EdDSA (RFC 8037).
/// Verification only: no private keys.
///
/// Point decoding follows RFC 8032 §5.1.3 strictly (y must be reduced, the
/// sign of x = 0 must be 0), S must be canonical (S < L), and the group
/// equation is checked without the cofactor ([S]B = R + [k]A, which RFC 8032
/// allows), by comparing the encoding of [S]B - [k]A with R, as OpenSSL (the
/// Node.js SDK) and Go do. The arithmetic is variable-time, which is fine for
/// verification: every input is public.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha512;

import 'bigint.dart';

final BigInt _p = (BigInt.one << 255) - BigInt.from(19);
final BigInt _d =
    (_p - BigInt.from(121665)) * BigInt.from(121666).modInverse(_p) % _p;
final BigInt _d2 = _d * BigInt.two % _p;
final BigInt _sqrtM1 = BigInt.two.modPow((_p - BigInt.one) >> 2, _p);
final BigInt _l = (BigInt.one << 252) +
    BigInt.parse('27742317777372353535851937790883648493');
final BigInt _sqrtExp = (_p - BigInt.from(5)) >> 3;

/// The order L of the prime-order subgroup.
BigInt get ed25519L => _l;

/// A point in extended twisted Edwards coordinates (X:Y:Z:T), x = X/Z,
/// y = Y/Z, x*y = T/Z.
final class EdwardsPoint {
  const EdwardsPoint._(this.x, this.y, this.z, this.t);

  static final EdwardsPoint identity =
      EdwardsPoint._(BigInt.zero, BigInt.one, BigInt.one, BigInt.zero);

  final BigInt x;
  final BigInt y;
  final BigInt z;
  final BigInt t;

  EdwardsPoint _negate() => EdwardsPoint._((_p - x) % _p, y, z, (_p - t) % _p);
}

final EdwardsPoint _base = ed25519Decode(Uint8List.fromList([
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, //
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
]))!;

/// Decodes a 32-byte point encoding (RFC 8032 §5.1.3); null when it is not
/// a canonical encoding of a curve point.
EdwardsPoint? ed25519Decode(List<int> encoded) {
  if (encoded.length != 32) return null;
  final bytes = Uint8List.fromList(encoded);
  final sign = bytes[31] >> 7;
  bytes[31] &= 0x7f;
  final y = bigIntFromBytesLE(bytes);
  if (y >= _p) return null;
  final y2 = y * y % _p;
  final u = (y2 - BigInt.one) % _p;
  final v = (_d * y2 + BigInt.one) % _p;
  final v3 = v * v % _p * v % _p;
  final v7 = v3 * v3 % _p * v % _p;
  var x = u * v3 % _p * (u * v7 % _p).modPow(_sqrtExp, _p) % _p;
  final vx2 = v * x % _p * x % _p;
  if (vx2 == u) {
    // x is a square root of u/v.
  } else if (vx2 == (_p - u) % _p) {
    x = x * _sqrtM1 % _p;
  } else {
    return null;
  }
  if (x == BigInt.zero && sign == 1) return null;
  if ((x.isOdd ? 1 : 0) != sign) x = (_p - x) % _p;
  return EdwardsPoint._(x, y, BigInt.one, x * y % _p);
}

/// Encodes a point (RFC 8032 §5.1.2).
Uint8List ed25519Encode(EdwardsPoint point) {
  final zi = point.z.modInverse(_p);
  final x = point.x * zi % _p;
  final y = point.y * zi % _p;
  final out = bigIntToBytesLE(y, 32);
  if (x.isOdd) out[31] |= 0x80;
  return out;
}

/// [k]B. Exposed for the test-only signer; the library itself never signs.
EdwardsPoint ed25519MultiplyBase(BigInt k) =>
    _shamir(k, _base, BigInt.zero, EdwardsPoint.identity);

/// Verifies [signature] (R || S, 64 bytes) over [message] with the encoded
/// public key [publicKey] (32 bytes).
bool ed25519Verify(
  List<int> publicKey,
  List<int> message,
  List<int> signature,
) {
  final a = ed25519Decode(publicKey);
  if (a == null) return false;
  return ed25519VerifyDecoded(a, publicKey, message, signature);
}

/// Like [ed25519Verify] with the public key already decoded ([a] must be
/// the decoding of [publicKey]).
bool ed25519VerifyDecoded(
  EdwardsPoint a,
  List<int> publicKey,
  List<int> message,
  List<int> signature,
) {
  if (publicKey.length != 32 || signature.length != 64) return false;
  final rBytes = Uint8List.fromList(signature.sublist(0, 32));
  final s = bigIntFromBytesLE(signature.sublist(32, 64));
  if (s >= _l) return false; // non-canonical S (malleability)
  if (ed25519Decode(rBytes) == null) return false;
  final input = Uint8List(64 + message.length)
    ..setRange(0, 32, rBytes)
    ..setRange(32, 64, publicKey)
    ..setRange(64, 64 + message.length, message);
  final k = bigIntFromBytesLE(sha512.convert(input).bytes) % _l;
  final check = _shamir(s, _base, k, a._negate());
  return constantTimeEquals(ed25519Encode(check), rBytes);
}

// add-2008-hwcd-3: complete for a = -1 and non-square d (also doubles).
EdwardsPoint _add(EdwardsPoint p, EdwardsPoint q) {
  final a = (p.y - p.x) * (q.y - q.x) % _p;
  final b = (p.y + p.x) * (q.y + q.x) % _p;
  final c = p.t * _d2 % _p * q.t % _p;
  final d = p.z * q.z % _p * BigInt.two % _p;
  final e = b - a;
  final f = d - c;
  final g = d + c;
  final h = b + a;
  return EdwardsPoint._(e * f % _p, g * h % _p, f * g % _p, e * h % _p);
}

EdwardsPoint _shamir(BigInt a, EdwardsPoint p, BigInt b, EdwardsPoint q) {
  final pq = _add(p, q);
  final width = a.bitLength > b.bitLength ? a.bitLength : b.bitLength;
  final abits = bitsOf(a, width);
  final bbits = bitsOf(b, width);
  var r = EdwardsPoint.identity;
  for (var i = 0; i < width; i++) {
    r = _add(r, r);
    final x = abits.codeUnitAt(i) == 0x31;
    final y = bbits.codeUnitAt(i) == 0x31;
    if (x && y) {
      r = _add(r, pq);
    } else if (x) {
      r = _add(r, p);
    } else if (y) {
      r = _add(r, q);
    }
  }
  return r;
}
