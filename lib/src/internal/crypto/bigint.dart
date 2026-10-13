import 'dart:typed_data';

const String _hexDigits = '0123456789abcdef';

/// Big-endian unsigned integer (OS2IP, RFC 8017 §4.2).
BigInt bigIntFromBytes(List<int> bytes) {
  if (bytes.isEmpty) return BigInt.zero;
  final sb = StringBuffer();
  for (final b in bytes) {
    sb
      ..writeCharCode(_hexDigits.codeUnitAt((b >> 4) & 0xf))
      ..writeCharCode(_hexDigits.codeUnitAt(b & 0xf));
  }
  return BigInt.parse(sb.toString(), radix: 16);
}

/// Little-endian unsigned integer (RFC 8032 encoding).
BigInt bigIntFromBytesLE(List<int> bytes) =>
    bigIntFromBytes(bytes.reversed.toList(growable: false));

/// Big-endian encoding of [value] in exactly [length] bytes (I2OSP, RFC 8017
/// §4.1). Throws [ArgumentError] when [value] is negative or does not fit.
Uint8List bigIntToBytes(BigInt value, int length) {
  if (value.isNegative || value.bitLength > length * 8) {
    throw ArgumentError('integer too large');
  }
  final out = Uint8List(length);
  if (value == BigInt.zero) return out;
  final hex = value.toRadixString(16);
  final digits = hex.length.isOdd ? '0$hex' : hex;
  final n = digits.length ~/ 2;
  for (var i = 0; i < n; i++) {
    out[length - n + i] =
        int.parse(digits.substring(2 * i, 2 * i + 2), radix: 16);
  }
  return out;
}

/// Little-endian encoding of [value] in exactly [length] bytes.
Uint8List bigIntToBytesLE(BigInt value, int length) {
  final be = bigIntToBytes(value, length);
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = be[length - 1 - i];
  }
  return out;
}

/// Compares two byte strings without an early exit on the first difference.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= (a[i] ^ b[i]) & 0xff;
  }
  return diff == 0;
}

/// The bits of [v] (most significant first) padded to [width].
String bitsOf(BigInt v, int width) => v.toRadixString(2).padLeft(width, '0');
