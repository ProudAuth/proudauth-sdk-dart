/// RSASSA-PKCS1-v1_5 and RSASSA-PSS signature verification with SHA-256
/// (RFC 8017 §8.1.2 and §8.2.2), for RS256 and PS256 (RFC 7518 §3.3, §3.5).
/// Verification only: this library never handles private keys.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;

import 'bigint.dart';

/// An RSA public key.
final class RsaPublicKey {
  RsaPublicKey._(this.n, this.e)
      : bitLength = n.bitLength,
        size = (n.bitLength + 7) >> 3;

  /// Validates the components: an odd modulus and an odd public exponent
  /// with 3 <= e < n. Returns null for anything else (e = 1, for example,
  /// would make every message its own signature).
  static RsaPublicKey? fromComponents(BigInt n, BigInt e) {
    if (n.sign <= 0 || !n.isOdd) return null;
    if (e < BigInt.from(3) || !e.isOdd || e >= n) return null;
    return RsaPublicKey._(n, e);
  }

  final BigInt n;
  final BigInt e;

  /// Modulus length in bits.
  final int bitLength;

  /// Modulus length in bytes (k in RFC 8017).
  final int size;
}

/// DER prefix of the SHA-256 DigestInfo (RFC 8017 §9.2 note 1), with the
/// NULL parameters: the only encoding accepted.
const List<int> _sha256DigestInfo = [
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, //
  0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
];

/// RSAVP1 (RFC 8017 §5.2.2) with the signature length check of §8.x step 1:
/// the signature must be exactly k bytes and its representative below n.
BigInt? _rsavp1(RsaPublicKey key, List<int> signature) {
  if (signature.length != key.size) return null;
  final s = bigIntFromBytes(signature);
  if (s >= key.n) return null;
  return s.modPow(key.e, key.n);
}

/// RS256: RSASSA-PKCS1-v1_5-VERIFY with SHA-256. The expected encoding is
/// rebuilt and compared as a whole (no parsing of the decrypted block).
bool rsaVerifyPkcs1v15Sha256(
  RsaPublicKey key,
  List<int> message,
  List<int> signature,
) {
  final k = key.size;
  final tLen = _sha256DigestInfo.length + 32;
  if (k < tLen + 11) return false;
  final m = _rsavp1(key, signature);
  if (m == null) return false;
  final Uint8List em;
  try {
    em = bigIntToBytes(m, k);
  } on ArgumentError {
    return false;
  }
  final expected = Uint8List(k);
  expected[0] = 0x00;
  expected[1] = 0x01;
  final psEnd = k - tLen - 1;
  for (var i = 2; i < psEnd; i++) {
    expected[i] = 0xff;
  }
  expected[psEnd] = 0x00;
  expected.setRange(
      psEnd + 1, psEnd + 1 + _sha256DigestInfo.length, _sha256DigestInfo);
  expected.setRange(k - 32, k, sha256.convert(message).bytes);
  return constantTimeEquals(em, expected);
}

/// PS256: RSASSA-PSS-VERIFY with SHA-256, MGF1-SHA-256 and a salt as long
/// as the hash (32 bytes), as JWA requires and the Node.js SDK enforces.
bool rsaVerifyPssSha256(
  RsaPublicKey key,
  List<int> message,
  List<int> signature,
) {
  const hLen = 32;
  const sLen = 32;
  final m = _rsavp1(key, signature);
  if (m == null) return false;
  final emBits = key.bitLength - 1;
  final emLen = (emBits + 7) >> 3;
  // I2OSP(m, emLen) and the zero-bits check of EMSA-PSS-VERIFY step 6.
  if (m.bitLength > emBits) return false;
  final em = bigIntToBytes(m, emLen);
  if (emLen < hLen + sLen + 2) return false;
  if (em[emLen - 1] != 0xbc) return false;
  final dbLen = emLen - hLen - 1;
  final h = Uint8List.sublistView(em, dbLen, dbLen + hLen);
  final db = _mgf1Sha256(h, dbLen);
  for (var i = 0; i < dbLen; i++) {
    db[i] ^= em[i];
  }
  db[0] &= 0xff >> (8 * emLen - emBits);
  final padLen = emLen - hLen - sLen - 2;
  for (var i = 0; i < padLen; i++) {
    if (db[i] != 0) return false;
  }
  if (db[padLen] != 0x01) return false;
  final mPrime = Uint8List(8 + hLen + sLen);
  mPrime.setRange(8, 8 + hLen, sha256.convert(message).bytes);
  mPrime.setRange(8 + hLen, 8 + hLen + sLen, db, dbLen - sLen);
  return constantTimeEquals(sha256.convert(mPrime).bytes, h);
}

Uint8List _mgf1Sha256(List<int> seed, int length) {
  final out = Uint8List(length);
  final input = Uint8List(seed.length + 4)..setRange(0, seed.length, seed);
  var offset = 0;
  for (var counter = 0; offset < length; counter++) {
    input[seed.length] = (counter >> 24) & 0xff;
    input[seed.length + 1] = (counter >> 16) & 0xff;
    input[seed.length + 2] = (counter >> 8) & 0xff;
    input[seed.length + 3] = counter & 0xff;
    final block = sha256.convert(input).bytes;
    final n = length - offset < block.length ? length - offset : block.length;
    out.setRange(offset, offset + n, block);
    offset += n;
  }
  return out;
}
