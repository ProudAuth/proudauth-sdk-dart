import 'dart:convert';

import 'package:proudauth_sdk/src/internal/base64url.dart';
import 'package:proudauth_sdk/src/internal/json.dart';
import 'package:test/test.dart';

String? _reason(String text) {
  try {
    parseStrictJson(text);
    return null;
  } on StrictJsonException catch (e) {
    return e.reason.name;
  } catch (_) {
    return 'other';
  }
}

void main() {
  group('strict JSON', () {
    test('parses valid JSON like jsonDecode', () {
      for (final t in [
        '{}',
        '[]',
        r'{"a":[1,2,{"b":null}],"c":"\u00e9\n","d":-1.5e3,"e":true,"f":false}',
        ' "x" ',
        '0',
        '{"a":{"a":1}}',
        r'"\ud83d\ude00 \"q\" \\ \/ \b\f\r\t"',
        '[1e400, -0.0, 12345678901234567890]',
      ]) {
        expect(parseStrictJson(t), jsonDecode(t), reason: t);
      }
      final m = parseStrictJson('{"b":1,"a":2}')! as Map<String, Object?>;
      expect(m.keys, ['b', 'a'], reason: 'insertion order is kept');
      expect(parseStrictJson('7'), isA<int>());
      expect(parseStrictJson('7.0'), isA<double>());
    });

    test('rejects duplicate member names, including escaped ones', () {
      expect(_reason('{"a":1,"a":2}'), 'duplicate');
      expect(_reason(r'{"iss":"x","\u0069ss":"y"}'), 'duplicate');
      expect(_reason('{"x":{"a":1,"a":1}}'), 'duplicate');
      expect(_reason('[{"a":1,"a":1}]'), 'duplicate');
    });

    test(
        'rejects trailing data, invalid grammar, lone surrogates and deep nesting',
        () {
      for (final t in [
        '{} {}',
        '{}x',
        '{"a":1,}',
        '[1,]',
        "{'a':1}",
        '{"a":01}',
        '{"a":.5}',
        '{"a":NaN}',
        '{"a":"\t"}',
        r'{"a":"\x41"}',
        r'{"a":"\ud800"}',
        r'{"a":"\udc00\ud800"}',
        '\uFEFF{}',
        '',
        '{"a":1',
        '{"a":-}',
        '{"a":1.}',
        '{"a":1e}',
        r'{"a":"\u12"}',
        '[' * 34 + ']' * 34,
      ]) {
        expect(_reason(t), 'malformed', reason: t);
      }
      expect(() => parseStrictJson('[' * 33 + ']' * 33), returnsNormally);
    });

    test(
        'keeps a UTF-8 byte-order mark so it is rejected, and rejects invalid UTF-8',
        () {
      expect(decodeUtf8Strict([0xEF, 0xBB, 0xBF, 0x7b, 0x7d]), '\uFEFF{}');
      expect(() => parseStrictJsonBytes(utf8.encode('\uFEFF{}')),
          throwsA(isA<StrictJsonException>()));
      for (final bad in [
        [0xC0, 0x80], // overlong
        [0xED, 0xA0, 0x80], // encoded surrogate
        [0xFF],
      ]) {
        expect(() => decodeUtf8Strict(bad), throwsFormatException);
      }
    });
  });

  group('base64url', () {
    test('decodes only canonical unpadded base64url', () {
      expect(utf8.decode(decodeBase64UrlStrict('aGk')), 'hi');
      expect(decodeBase64UrlStrict(''), isEmpty);
      for (final s in [
        'aGk=',
        'aG+k',
        'aG/k',
        'aGl',
        'a',
        'aG k',
        'aGk\u00e9'
      ]) {
        expect(() => decodeBase64UrlStrict(s), throwsFormatException,
            reason: s);
      }
    });

    test('round-trips every length', () {
      for (var n = 0; n < 70; n++) {
        final bytes = List<int>.generate(n, (i) => (i * 37 + n) & 0xff);
        expect(decodeBase64UrlStrict(encodeBase64Url(bytes)), bytes);
      }
    });

    test('JWK members tolerate padding but not foreign characters', () {
      expect(utf8.decode(decodeBase64UrlLenient('aGk=')), 'hi');
      expect(utf8.decode(decodeBase64UrlLenient('aGl')), 'hi');
      expect(() => decodeBase64UrlLenient('aG+k'), throwsFormatException);
    });
  });
}
