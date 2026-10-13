import 'dart:typed_data';

Uint8List hexDecode(String s) {
  if (s.length.isOdd) throw FormatException('odd hex length', s);
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(2 * i, 2 * i + 2), radix: 16);
  }
  return out;
}

String hexEncode(List<int> bytes) =>
    bytes.map((b) => (b & 0xff).toRadixString(16).padLeft(2, '0')).join();
