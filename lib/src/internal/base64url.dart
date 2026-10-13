import 'dart:convert';
import 'dart:typed_data';

const String _alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

final List<int> _decodeTable = () {
  final t = List<int>.filled(128, -1);
  for (var i = 0; i < _alphabet.length; i++) {
    t[_alphabet.codeUnitAt(i)] = i;
  }
  return t;
}();

/// Strict, canonical base64url as used by JWS compact serialization: no
/// padding, no characters outside the URL-safe alphabet and no non-zero pad
/// bits (the same input always has exactly one encoding). Throws
/// [FormatException] otherwise.
Uint8List decodeBase64UrlStrict(String s) => _decode(s, canonical: true);

/// base64url for JWK members: tolerates trailing `=` padding and non-zero
/// pad bits (the key set is trusted configuration), but still rejects
/// characters outside the URL-safe alphabet.
Uint8List decodeBase64UrlLenient(String s) {
  var end = s.length;
  while (end > 0 && s.codeUnitAt(end - 1) == 0x3d) {
    end--;
  }
  return _decode(s.substring(0, end), canonical: false);
}

/// Unpadded base64url.
String encodeBase64Url(List<int> bytes) {
  final s = base64Url.encode(bytes);
  var end = s.length;
  while (end > 0 && s.codeUnitAt(end - 1) == 0x3d) {
    end--;
  }
  return s.substring(0, end);
}

Uint8List _decode(String s, {required bool canonical}) {
  final len = s.length;
  if (len % 4 == 1) throw const FormatException('invalid base64url length');
  final out = Uint8List(len * 3 ~/ 4);
  var o = 0;
  var acc = 0;
  var bits = 0;
  for (var i = 0; i < len; i++) {
    final c = s.codeUnitAt(i);
    final v = c < 128 ? _decodeTable[c] : -1;
    if (v < 0) throw const FormatException('invalid base64url character');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  if (canonical && acc != 0) {
    throw const FormatException('non-canonical base64url');
  }
  return o == out.length ? out : Uint8List.sublistView(out, 0, o);
}
