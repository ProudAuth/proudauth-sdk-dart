/// ECDSA verification on NIST P-256 (FIPS 186-5 §6.4.2, SEC 1 §4.1.4) for
/// ES256 (RFC 7518 §3.4). Verification only: no private keys, no nonces.
///
/// The arithmetic is variable-time, which is fine for verification: every
/// input (public key, message, signature) is public.
library;

import 'bigint.dart';

final BigInt _p = BigInt.parse(
    'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
    radix: 16);
final BigInt _b = BigInt.parse(
    '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
    radix: 16);
final BigInt _n = BigInt.parse(
    'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
    radix: 16);
final BigInt _gx = BigInt.parse(
    '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
    radix: 16);
final BigInt _gy = BigInt.parse(
    '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
    radix: 16);

final BigInt _two = BigInt.two;
final BigInt _three = BigInt.from(3);
final BigInt _four = BigInt.from(4);
final BigInt _eight = BigInt.from(8);

/// The field prime p of P-256.
BigInt get p256P => _p;

/// The group order n of P-256.
BigInt get p256N => _n;

/// Whether (x, y) is a point of P-256 with coordinates in [0, p). The curve
/// has cofactor 1, so every such point is in the prime-order group.
bool p256IsOnCurve(BigInt x, BigInt y) {
  if (x.isNegative || y.isNegative || x >= _p || y >= _p) return false;
  final lhs = y * y % _p;
  final rhs = (x * x % _p * x - _three * x + _b) % _p;
  return lhs == rhs;
}

/// Verifies a JWS ES256 signature: [signature] is r || s, 32 bytes each;
/// [hash] is the SHA-256 digest of the signing input. r and s must be in
/// [1, n-1]; the public key must be on the curve.
bool p256Verify(BigInt qx, BigInt qy, List<int> hash, List<int> signature) {
  if (signature.length != 64 || hash.length != 32) return false;
  if (!p256IsOnCurve(qx, qy)) return false;
  final r = bigIntFromBytes(signature.sublist(0, 32));
  final s = bigIntFromBytes(signature.sublist(32, 64));
  if (r.sign <= 0 || r >= _n || s.sign <= 0 || s >= _n) return false;
  // The digest is as long as n, so no truncation is needed.
  final e = bigIntFromBytes(hash);
  final w = s.modInverse(_n);
  final u1 = e * w % _n;
  final u2 = r * w % _n;
  final g = _Jacobian(_gx, _gy, BigInt.one);
  final q = _Jacobian(qx, qy, BigInt.one);
  final point = _shamir(u1, g, u2, q);
  if (point.isInfinity) return false;
  final x = _affine(point).$1;
  return x % _n == r;
}

/// [k]G in affine coordinates, or null for the point at infinity.
/// Exposed for the test-only signer; the library itself never signs.
(BigInt, BigInt)? p256MultiplyBase(BigInt k) => p256Multiply(k, _gx, _gy);

/// [k](x, y) in affine coordinates, or null for the point at infinity.
(BigInt, BigInt)? p256Multiply(BigInt k, BigInt x, BigInt y) {
  final r = _shamir(
      k % _n, _Jacobian(x, y, BigInt.one), BigInt.zero, _Jacobian.infinity);
  return r.isInfinity ? null : _affine(r);
}

final class _Jacobian {
  const _Jacobian(this.x, this.y, this.z);

  static final _Jacobian infinity =
      _Jacobian(BigInt.one, BigInt.one, BigInt.zero);

  final BigInt x;
  final BigInt y;
  final BigInt z;

  bool get isInfinity => z == BigInt.zero;
}

(BigInt, BigInt) _affine(_Jacobian p) {
  final zi = p.z.modInverse(_p);
  final zi2 = zi * zi % _p;
  return (p.x * zi2 % _p, p.y * zi2 % _p * zi % _p);
}

// dbl-2001-b (a = -3).
_Jacobian _double(_Jacobian p) {
  if (p.isInfinity || p.y == BigInt.zero) return _Jacobian.infinity;
  final delta = p.z * p.z % _p;
  final gamma = p.y * p.y % _p;
  final beta = p.x * gamma % _p;
  final alpha = _three * (p.x - delta) * (p.x + delta) % _p;
  final x3 = (alpha * alpha - _eight * beta) % _p;
  final yz = p.y + p.z;
  final z3 = (yz * yz - gamma - delta) % _p;
  final y3 = (alpha * (_four * beta - x3) - _eight * gamma * gamma) % _p;
  return _Jacobian(x3, y3, z3);
}

// General Jacobian addition with the doubling and inverse special cases.
_Jacobian _add(_Jacobian p, _Jacobian q) {
  if (p.isInfinity) return q;
  if (q.isInfinity) return p;
  final z1z1 = p.z * p.z % _p;
  final z2z2 = q.z * q.z % _p;
  final u1 = p.x * z2z2 % _p;
  final u2 = q.x * z1z1 % _p;
  final s1 = p.y * q.z % _p * z2z2 % _p;
  final s2 = q.y * p.z % _p * z1z1 % _p;
  if (u1 == u2) {
    return s1 == s2 ? _double(p) : _Jacobian.infinity;
  }
  final h = (u2 - u1) % _p;
  final r = (s2 - s1) % _p;
  final hh = h * h % _p;
  final hhh = h * hh % _p;
  final v = u1 * hh % _p;
  final x3 = (r * r - hhh - _two * v) % _p;
  final y3 = (r * (v - x3) - s1 * hhh) % _p;
  final z3 = p.z * q.z % _p * h % _p;
  return _Jacobian(x3, y3, z3);
}

// [a]P + [b]Q with Shamir's trick.
_Jacobian _shamir(BigInt a, _Jacobian p, BigInt b, _Jacobian q) {
  final pq = _add(p, q);
  final width = a.bitLength > b.bitLength ? a.bitLength : b.bitLength;
  final abits = bitsOf(a, width);
  final bbits = bitsOf(b, width);
  var r = _Jacobian.infinity;
  for (var i = 0; i < width; i++) {
    r = _double(r);
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
