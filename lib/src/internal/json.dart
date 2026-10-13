/// Strict JSON parsing for security-sensitive inputs (JOSE headers, JWT
/// payloads, JWKS documents, introspection and token responses), a port of
/// the Node.js SDK's `internal/json.ts`.
///
/// `jsonDecode` silently keeps the last of several members with the same
/// name, so two parties can read different values from one document. This
/// parser implements the complete RFC 8259 grammar and rejects duplicate
/// member names (compared after unescaping, so `"iss"` and `"\u0069ss"`
/// collide), excessive nesting, lone surrogates and trailing data.
library;

import 'dart:convert';
import 'dart:typed_data';

/// Why strict parsing failed.
enum StrictJsonFailure { malformed, duplicate }

/// A strict-parsing failure. Never contains the input.
final class StrictJsonException implements Exception {
  const StrictJsonException(this.reason);

  final StrictJsonFailure reason;

  @override
  String toString() => reason == StrictJsonFailure.duplicate
      ? 'duplicate JSON member name'
      : 'malformed JSON';
}

/// Default nesting limit, matching the Go and Node.js SDKs (values deeper
/// than 32 levels are rejected).
const int defaultMaxJsonDepth = 32;

const StrictJsonException _malformed =
    StrictJsonException(StrictJsonFailure.malformed);
const StrictJsonException _duplicate =
    StrictJsonException(StrictJsonFailure.duplicate);

/// Parses [text] strictly. Objects become `Map<String, Object?>` (insertion
/// ordered), arrays `List<Object?>`, numbers `int` (integer literals that fit)
/// or `double`.
Object? parseStrictJson(String text, {int maxDepth = defaultMaxJsonDepth}) {
  final parser = _Parser(text, maxDepth);
  final value = parser.value(0);
  parser.skipWhitespace();
  if (parser.i != text.length) throw _malformed;
  return value;
}

/// Decodes UTF-8 strictly: invalid sequences (including encoded surrogates)
/// are rejected, and a leading byte-order mark is kept in the result (Dart's
/// decoder would drop it) so that strict JSON parsing rejects it, like the
/// Node.js SDK.
String decodeUtf8Strict(List<int> bytes) {
  final text = const Utf8Decoder(allowMalformed: false).convert(bytes);
  return _hasBom(bytes) ? '\uFEFF$text' : text;
}

/// Decodes UTF-8 replacing invalid sequences (like Node's `Buffer#toString`),
/// keeping a leading byte-order mark.
String decodeUtf8Lenient(List<int> bytes) {
  final text = const Utf8Decoder(allowMalformed: true).convert(bytes);
  return _hasBom(bytes) ? '\uFEFF$text' : text;
}

bool _hasBom(List<int> b) =>
    b.length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF;

/// Parses a UTF-8 JSON document strictly ([decodeUtf8Strict] then
/// [parseStrictJson]).
Object? parseStrictJsonBytes(Uint8List bytes) {
  final String text;
  try {
    text = decodeUtf8Strict(bytes);
  } on FormatException {
    throw _malformed;
  }
  return parseStrictJson(text);
}

/// Whether [v] is a JSON object.
bool isJsonObject(Object? v) => v is Map<String, Object?>;

class _Parser {
  _Parser(this.text, this.maxDepth) : n = text.length;

  final String text;
  final int maxDepth;
  final int n;
  int i = 0;

  int _at(int k) => k < n ? text.codeUnitAt(k) : -1;

  void skipWhitespace() {
    while (i < n) {
      final c = text.codeUnitAt(i);
      if (c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d) {
        i++;
      } else {
        break;
      }
    }
  }

  Object? value(int depth) {
    if (depth > maxDepth) throw _malformed;
    skipWhitespace();
    if (i >= n) throw _malformed;
    final c = text.codeUnitAt(i);
    switch (c) {
      case 0x7b: // {
        i++;
        final map = <String, Object?>{};
        skipWhitespace();
        if (_at(i) == 0x7d) {
          i++;
          return map;
        }
        for (;;) {
          skipWhitespace();
          if (_at(i) != 0x22) throw _malformed;
          final key = string();
          if (map.containsKey(key)) throw _duplicate;
          skipWhitespace();
          if (_at(i) != 0x3a) throw _malformed;
          i++;
          map[key] = value(depth + 1);
          skipWhitespace();
          final d = _at(i);
          if (d == 0x2c) {
            i++;
            continue;
          }
          if (d == 0x7d) {
            i++;
            return map;
          }
          throw _malformed;
        }
      case 0x5b: // [
        i++;
        final list = <Object?>[];
        skipWhitespace();
        if (_at(i) == 0x5d) {
          i++;
          return list;
        }
        for (;;) {
          list.add(value(depth + 1));
          skipWhitespace();
          final d = _at(i);
          if (d == 0x2c) {
            i++;
            continue;
          }
          if (d == 0x5d) {
            i++;
            return list;
          }
          throw _malformed;
        }
      case 0x22: // "
        return string();
      case 0x74: // t
        if (text.startsWith('true', i)) {
          i += 4;
          return true;
        }
        throw _malformed;
      case 0x66: // f
        if (text.startsWith('false', i)) {
          i += 5;
          return false;
        }
        throw _malformed;
      case 0x6e: // n
        if (text.startsWith('null', i)) {
          i += 4;
          return null;
        }
        throw _malformed;
      default:
        return number();
    }
  }

  // -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
  num number() {
    final start = i;
    var integer = true;
    if (_at(i) == 0x2d) i++;
    final first = _at(i);
    if (first == 0x30) {
      i++;
    } else if (first >= 0x31 && first <= 0x39) {
      while (_isDigit(_at(i))) {
        i++;
      }
    } else {
      throw _malformed;
    }
    if (_at(i) == 0x2e) {
      integer = false;
      i++;
      if (!_isDigit(_at(i))) throw _malformed;
      while (_isDigit(_at(i))) {
        i++;
      }
    }
    final e = _at(i);
    if (e == 0x65 || e == 0x45) {
      integer = false;
      i++;
      final s = _at(i);
      if (s == 0x2b || s == 0x2d) i++;
      if (!_isDigit(_at(i))) throw _malformed;
      while (_isDigit(_at(i))) {
        i++;
      }
    }
    final literal = text.substring(start, i);
    if (integer) {
      final v = int.tryParse(literal);
      if (v != null) return v;
    }
    return double.parse(literal);
  }

  static bool _isDigit(int c) => c >= 0x30 && c <= 0x39;

  String string() {
    // text[i] == '"'
    i++;
    final start = i;
    StringBuffer? buf;
    var runStart = start;
    while (i < n) {
      final c = text.codeUnitAt(i);
      if (c == 0x22) {
        final String result;
        if (buf == null) {
          result = text.substring(start, i);
        } else {
          buf.write(text.substring(runStart, i));
          result = buf.toString();
        }
        i++;
        if (!_wellFormed(result)) throw _malformed;
        return result;
      }
      if (c == 0x5c) {
        buf ??= StringBuffer();
        buf.write(text.substring(runStart, i));
        i++;
        if (i >= n) throw _malformed;
        final e = text.codeUnitAt(i);
        switch (e) {
          case 0x75: // u
            if (i + 5 > n) throw _malformed;
            var cu = 0;
            for (var k = i + 1; k < i + 5; k++) {
              final h = _hex(text.codeUnitAt(k));
              if (h < 0) throw _malformed;
              cu = (cu << 4) | h;
            }
            buf.writeCharCode(cu);
            i += 5;
          case 0x22:
            buf.write('"');
            i++;
          case 0x5c:
            buf.write(r'\');
            i++;
          case 0x2f:
            buf.write('/');
            i++;
          case 0x62:
            buf.write('\b');
            i++;
          case 0x66:
            buf.write('\f');
            i++;
          case 0x6e:
            buf.write('\n');
            i++;
          case 0x72:
            buf.write('\r');
            i++;
          case 0x74:
            buf.write('\t');
            i++;
          default:
            throw _malformed;
        }
        runStart = i;
        continue;
      }
      if (c < 0x20) throw _malformed;
      i++;
    }
    throw _malformed;
  }

  static int _hex(int c) {
    if (c >= 0x30 && c <= 0x39) return c - 0x30;
    if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
    if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
    return -1;
  }

  /// No lone surrogates (String.prototype.isWellFormed).
  static bool _wellFormed(String s) {
    for (var k = 0; k < s.length; k++) {
      final c = s.codeUnitAt(k);
      if (c >= 0xD800 && c <= 0xDBFF) {
        if (k + 1 >= s.length) return false;
        final d = s.codeUnitAt(k + 1);
        if (d < 0xDC00 || d > 0xDFFF) return false;
        k++;
      } else if (c >= 0xDC00 && c <= 0xDFFF) {
        return false;
      }
    }
    return true;
  }
}
