import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' show Hmac, sha256;
import 'package:http/http.dart' as http;
import 'package:proudauth_sdk/src/internal/base64url.dart';
import 'package:proudauth_sdk/verifier.dart';
import 'package:test/test.dart';

import 'support/server.dart';
import 'support/signer.dart';

const _iss = 'https://id.test/realms/main';
const _aud = 'https://api.test/orders';
const _now = 1800000000; // seconds

Map<String, Object?> _claims([Map<String, Object?> extra = const {}]) => {
      'iss': _iss,
      'sub': 'usr_1',
      'aud': _aud,
      'client_id': 'customer-web-bff',
      'iat': _now,
      'exp': _now + 300,
      'jti': 'tok_${randomHex(6)}',
      'sid': 'ses_1',
      'scope': 'orders:read orders:create',
      'org_id': 'org_a',
      'token_kind': 'user_access',
      'authz_version': 43,
      ...extra,
    };

Matcher _code(VerifierErrorCode code) =>
    throwsA(isA<VerifierException>().having((e) => e.code, 'code', code));

Future<void> _rejects(Future<Object?> f, VerifierErrorCode code) =>
    expectLater(f, _code(code));

String _hs256(String header, String payload, List<int> secret) {
  final input = '${b64(header)}.${b64(payload)}';
  return '$input.${b64(Hmac(sha256, secret).convert(utf8.encode(input)).bytes)}';
}

void main() {
  late TestKey es, rs, ps, ed;
  late TestServer jwks;
  late http.Client client;
  late List<Map<String, Object?>> published;
  var status = 200;

  setUpAll(() async {
    es = makeKey('ES256', kid: 'es-1');
    rs = makeKey('RS256', kid: 'rs-1', rsaIndex: 0);
    ps = makeKey('PS256', kid: 'ps-1', rsaIndex: 1);
    ed = makeKey('EdDSA', kid: 'ed-1');
    published = [es.jwk, rs.jwk, ps.jwk, ed.jwk];
    jwks = await TestServer.start((req, _) {
      if (status != 200) return respondJson(req, status, {'error': 'down'});
      return respondJson(req, 200, {'keys': published});
    });
    client = http.Client();
  });
  tearDownAll(() async {
    client.close();
    await jwks.close();
  });

  Verifier make({
    TestClock? clock,
    String? jwksUrl,
    List<String>? algorithms,
    List<String>? acceptedKinds,
    int maxTokenBytes = 8192,
    Duration clockSkew = const Duration(seconds: 30),
    Duration minRefreshInterval = const Duration(seconds: 60),
  }) {
    final c = clock ?? TestClock(fromSeconds(_now));
    return Verifier(
      issuer: _iss,
      audience: _aud,
      jwksUrl: jwksUrl ?? '${jwks.url}/jwks',
      now: c.call,
      minRefreshInterval: minRefreshInterval,
      algorithms: algorithms,
      acceptedKinds: acceptedKinds,
      maxTokenBytes: maxTokenBytes,
      clockSkew: clockSkew,
      httpClient: client,
    );
  }

  test('accepts a valid token for every allowlisted algorithm', () async {
    final v = make();
    for (final k in [es, rs, ps, ed]) {
      final c = await v.verify(signJwt(k, _claims()));
      expect(c.subject, 'usr_1', reason: k.alg);
      expect(c.audience, _aud);
      expect(c.issuer, _iss);
      expect(c.clientId, 'customer-web-bff');
      expect(c.scopes, ['orders:read', 'orders:create']);
      expect(c.orgId, 'org_a');
      expect(c.sessionId, 'ses_1');
      expect(c.tokenKind, 'user_access');
      expect(c.authzVersion, 43);
      expect(c.online, isFalse);
      expect(c.expiry, fromSeconds(_now + 300));
      expect(c.issuedAt, fromSeconds(_now));
      expect(() => c.scopes.add('x'), throwsUnsupportedError);
    }
    expect(v.fetchCount, 1, reason: 'keys are cached');
  });

  test('accepts application/at+jwt and a case-insensitive typ', () async {
    final v = make();
    await v.verify(signJwt(es, _claims(), {'typ': 'application/at+jwt'}));
    await v.verify(signJwt(es, _claims(), {'typ': 'AT+JWT'}));
  });

  test('accepts the audience as a single-element array', () async {
    await make().verify(signJwt(
        es,
        _claims({
          'aud': [_aud]
        })));
  });

  test('preserves the actor of exchanged tokens', () async {
    final c = await make().verify(signJwt(
        es,
        _claims({
          'token_kind': 'exchange_access',
          'act': {
            'sub': 'svc_orders',
            'iss': _iss,
            'act': {'sub': 'svc_gw'},
          },
        })));
    expect(c.actor?.subject, 'svc_orders');
    expect(c.actor?.issuer, _iss);
    expect(c.actor?.act?.subject, 'svc_gw');
  });

  test('rejects a token from another issuer without fetching keys (TEST-003)',
      () async {
    final v = make();
    await _rejects(
        v.verify(
            signJwt(es, _claims({'iss': 'https://evil.test/realms/main'}))),
        VerifierErrorCode.issuer);
    await _rejects(v.verify(signJwt(es, _claims({'iss': '$_iss/'}))),
        VerifierErrorCode.issuer);
    await _rejects(v.verify(signJwt(es, _claims({'iss': null}))),
        VerifierErrorCode.issuer);
    await _rejects(
        v.verify(signJwt(es, _claims({'iss': 42}))), VerifierErrorCode.issuer);
    expect(v.fetchCount, 0);
  });

  test('never fetches URLs from jku / x5u / jwk headers', () async {
    final evil = makeKey('ES256', kid: 'evil');
    final attacker = await TestServer.start((req, _) => respondJson(req, 200, {
          'keys': [evil.jwk]
        }));
    try {
      final tok = signJwt(evil, _claims(), {
        'jku': '${attacker.url}/jwks',
        'x5u': '${attacker.url}/cert',
        'jwk': evil.jwk,
      });
      await _rejects(make().verify(tok), VerifierErrorCode.unknownKey);
      expect(attacker.hits, 0);
    } finally {
      await attacker.close();
    }
  });

  test('rejects the wrong audience (TEST-001)', () async {
    final v = make();
    for (final aud in [
      'https://api.test/billing',
      [_aud, 'https://api.test/billing'],
      <String>[],
      null,
      '$_aud/',
    ]) {
      await _rejects(v.verify(signJwt(es, _claims({'aud': aud}))),
          VerifierErrorCode.audience);
    }
  });

  test('rejects alg "none" without fetching (TEST-004)', () async {
    final v = make();
    for (final alg in ['none', 'None']) {
      final tok = '${b64(jsonEncode({
            'alg': alg,
            'typ': 'at+jwt',
            'kid': es.kid
          }))}.${b64(jsonEncode(_claims()))}.';
      await _rejects(v.verify(tok), VerifierErrorCode.algorithm);
    }
    expect(v.fetchCount, 0);
  });

  test(
      'rejects HS256 signed with the public key as the HMAC secret (key confusion)',
      () async {
    final v = make();
    final pem =
        '-----BEGIN PUBLIC KEY-----\n${base64.encode(utf8.encode(jsonEncode(rs.jwk)))}\n-----END PUBLIC KEY-----\n';
    for (final secret in [jsonEncode(rs.jwk), pem]) {
      final tok = _hs256(
          jsonEncode({'alg': 'HS256', 'typ': 'at+jwt', 'kid': rs.kid}),
          jsonEncode(_claims()),
          utf8.encode(secret));
      await _rejects(v.verify(tok), VerifierErrorCode.algorithm);
    }
    expect(v.fetchCount, 0);
  });

  test(
      'refuses symmetric, unsigned and unsupported algorithms in configuration',
      () {
    Matcher argError(String text) => throwsA(isA<ArgumentError>()
        .having((e) => '${e.message}', 'message', contains(text)));
    expect(() => make(algorithms: ['HS256']), argError('not allowed'));
    expect(() => make(algorithms: ['none']), argError('not allowed'));
    expect(() => make(algorithms: ['RS256', 'hs512']), argError('not allowed'));
    expect(() => make(algorithms: ['ES512']), argError('not supported'));
  });

  test('rejects an algorithm outside a narrowed allowlist', () async {
    final v = make(algorithms: ['ES256']);
    await v.verify(signJwt(es, _claims()));
    await _rejects(
        v.verify(signJwt(rs, _claims())), VerifierErrorCode.algorithm);
  });

  test('rejects a key whose JWK alg differs from the token alg', () async {
    // rs.jwk declares alg RS256; a PS256 token signed with the same RSA key is
    // refused.
    final tok = signJwt(rs.withKid(rs.kid, alg: 'PS256'), _claims(),
        {'alg': 'PS256', 'kid': rs.kid});
    await _rejects(make().verify(tok), VerifierErrorCode.algorithm);
  });

  test('rejects key-type confusion (ES256 header resolving to an RSA key)',
      () async {
    await _rejects(make().verify(signJwt(es, _claims(), {'kid': rs.kid})),
        VerifierErrorCode.algorithm); // rs.jwk declares alg RS256
    final loose = makeKey('RS256', kid: 'rs-noalg', jwkAlg: false, rsaIndex: 2);
    published.add(loose.jwk);
    try {
      await _rejects(make().verify(signJwt(es, _claims(), {'kid': loose.kid})),
          VerifierErrorCode.signature);
      final edLoose = Ed25519TestKey.generate(kid: 'ed-noalg')
          .withKid('ed-noalg', jwkAlg: false);
      published.add(edLoose.jwk);
      await _rejects(
          make().verify(signJwt(es, _claims(), {'kid': edLoose.kid})),
          VerifierErrorCode.signature);
    } finally {
      published
          .removeWhere((k) => k['kid'] == 'rs-noalg' || k['kid'] == 'ed-noalg');
    }
  });

  test(
      'rejects an ID token (typ JWT) and untyped tokens as access tokens (TEST-002)',
      () async {
    final v = make();
    for (final typ in ['JWT', null, 'logout+jwt', 7]) {
      await _rejects(v.verify(signJwt(es, _claims(), {'typ': typ})),
          VerifierErrorCode.tokenType);
    }
  });

  test('rejects expired tokens, honouring the clock skew (TEST-006)', () async {
    final clock = TestClock(fromSeconds(_now + 300 + 29));
    final v = make(clock: clock);
    await v.verify(signJwt(es, _claims())); // within the 30 s skew
    clock.now = fromSeconds(_now + 300 + 31);
    await _rejects(v.verify(signJwt(es, _claims())), VerifierErrorCode.expired);
    await _rejects(make().verify(signJwt(es, _claims({'exp': null}))),
        VerifierErrorCode.expired);
    await _rejects(make().verify(signJwt(es, _claims({'exp': _now - 100}))),
        VerifierErrorCode.expired);
    // A narrower skew is honoured too.
    final strict = make(
        clock: TestClock(fromSeconds(_now + 301)), clockSkew: Duration.zero);
    await _rejects(
        strict.verify(signJwt(es, _claims())), VerifierErrorCode.expired);
  });

  test('rejects not-yet-valid and future-issued tokens (TEST-006)', () async {
    final v = make();
    await _rejects(v.verify(signJwt(es, _claims({'nbf': _now + 120}))),
        VerifierErrorCode.notYetValid);
    await v.verify(signJwt(es, _claims({'nbf': _now + 20})));
    await _rejects(v.verify(signJwt(es, _claims({'iat': _now + 120}))),
        VerifierErrorCode.futureIssued);
  });

  test('rejects non-numeric time claims and malformed claim types', () async {
    final v = make();
    for (final extra in <Map<String, Object?>>[
      {'exp': '${_now + 300}'},
      {'nbf': true},
      {
        'scope': ['orders:read'],
      },
      {'act': 'admin'},
      {
        'act': {'sub': 'svc', 'iss': null},
      },
      {
        'act': {'sub': 7},
      },
      {'aud': 42},
      {
        'aud': [_aud, 1],
      },
      {'sub': 1},
      {'org_id': false},
    ]) {
      await _rejects(
          v.verify(signJwt(es, _claims(extra))), VerifierErrorCode.malformed);
    }
  });

  test('rejects duplicate JSON members in payload and header', () async {
    final v = make();
    final header = jsonEncode({'alg': 'ES256', 'typ': 'at+jwt', 'kid': es.kid});
    final body = jsonEncode(_claims());
    final open = body.substring(0, body.length - 1);
    await _rejects(v.verify(signRaw(es, header, '$open,"sub":"usr_admin"}')),
        VerifierErrorCode.duplicateClaim);
    await _rejects(v.verify(signRaw(es, header, '$open,"aud":"$_aud"}')),
        VerifierErrorCode.duplicateClaim);
    await _rejects(
        v.verify(signRaw(es, header, '$open,"\\u0069ss":"https://evil.test"}')),
        VerifierErrorCode.duplicateClaim);
    await _rejects(
        v.verify(signRaw(es, header, '$open,"act":{"sub":"a","sub":"b"}}')),
        VerifierErrorCode.duplicateClaim);
    await _rejects(
        v.verify(signRaw(
            es,
            '{"alg":"ES256","typ":"at+jwt","kid":"${es.kid}","kid":"${rs.kid}"}',
            body)),
        VerifierErrorCode.duplicateClaim);
    await _rejects(
        v.verify(signRaw(
            es,
            '{"alg":"none","typ":"at+jwt","kid":"${es.kid}","alg":"ES256"}',
            body)),
        VerifierErrorCode.duplicateClaim);
    expect(v.fetchCount, 0);
  });

  test('rejects trailing data and malformed structure', () async {
    final v = make();
    final header = jsonEncode({'alg': 'ES256', 'typ': 'at+jwt', 'kid': es.kid});
    final good = signJwt(es, _claims());
    await _rejects(v.verify('$good.extra'), VerifierErrorCode.malformed);
    await _rejects(v.verify(signRaw(es, header, '${jsonEncode(_claims())} {}')),
        VerifierErrorCode.malformed);
    await _rejects(v.verify(signRaw(es, '${header}x', jsonEncode(_claims()))),
        VerifierErrorCode.malformed);
    await _rejects(
        v.verify(signRaw(es, header, '[1,2]')), VerifierErrorCode.malformed);
    await _rejects(
        v.verify(signRaw(es, header, '\uFEFF${jsonEncode(_claims())}')),
        VerifierErrorCode.malformed);
    await _rejects(v.verify('a.b'), VerifierErrorCode.malformed);
    await _rejects(v.verify('a.b.c'), VerifierErrorCode.malformed);
    final parts = good.split('.');
    await _rejects(v.verify('${parts[0]}=.${parts[1]}.${parts[2]}'),
        VerifierErrorCode.malformed);
    await _rejects(
        v.verify('${parts[0]}.${parts[1]}.${parts[2].replaceAll('-', '+')}+'),
        VerifierErrorCode.malformed);
    await _rejects(
        v.verify(signRaw(
            es,
            jsonEncode({
              'alg': 'ES256',
              'typ': 'at+jwt',
              'kid': es.kid,
              'crit': ['exp'],
            }),
            jsonEncode(_claims()))),
        VerifierErrorCode.malformed);
    // Invalid UTF-8 in the payload.
    final badUtf8 =
        '${b64(header)}.${encodeBase64Url([0x7b, 0xff, 0x7d])}.${parts[2]}';
    await _rejects(v.verify(badUtf8), VerifierErrorCode.malformed);
    await _rejects(v.verify(''), VerifierErrorCode.missingToken);
    final deep = '{"iss":"$_iss","x":${'[' * 40}${']' * 40}}';
    await _rejects(
        v.verify(signRaw(es, header, deep)), VerifierErrorCode.malformed);
  });

  test('rejects an oversized token before parsing or fetching', () async {
    final v = make();
    final tok = signJwt(es, _claims({'pad': 'x' * 9000}));
    expect(tok.length, greaterThan(8192));
    await _rejects(v.verify(tok), VerifierErrorCode.tooLarge);
    await _rejects(make(maxTokenBytes: 100).verify(signJwt(es, _claims())),
        VerifierErrorCode.tooLarge);
    // Multi-byte characters count in bytes.
    await _rejects(make(maxTokenBytes: 10).verify('\u00e9' * 6),
        VerifierErrorCode.tooLarge);
    expect(v.fetchCount, 0);
  });

  test('rejects a tampered payload or signature', () async {
    final v = make();
    final parts = signJwt(es, _claims()).split('.');
    final forged = b64(jsonEncode(_claims({'sub': 'usr_admin'})));
    await _rejects(v.verify('${parts[0]}.$forged.${parts[2]}'),
        VerifierErrorCode.signature);
    final other = signJwt(makeKey('ES256', kid: es.kid), _claims());
    await _rejects(v.verify(other), VerifierErrorCode.signature);
    for (final k in [rs, ps, ed]) {
      final p = signJwt(k, _claims()).split('.');
      await _rejects(
          v.verify('${p[0]}.$forged.${p[2]}'), VerifierErrorCode.signature);
    }
  });

  test('rejects impersonation and unknown token kinds offline', () async {
    final v = make();
    await _rejects(
        v.verify(signJwt(
            es,
            _claims({
              'token_kind': 'impersonation_access',
              'act': {'sub': 'usr_agent'},
              'impersonation_grant_id': 'imp_1',
            }))),
        VerifierErrorCode.tokenKind);
    for (final extra in <Map<String, Object?>>[
      {'token_kind': null},
      {'token_kind': 'refresh'},
      {'sub': ''},
      {'client_id': null},
      {'jti': null},
    ]) {
      await _rejects(
          v.verify(signJwt(es, _claims(extra))), VerifierErrorCode.tokenKind);
    }
    expect(
        () => make(acceptedKinds: ['user_access', 'impersonation_access']),
        throwsA(isA<ArgumentError>().having(
            (e) => '${e.message}', 'message', contains('SupportGuard'))));
    final services = make(acceptedKinds: ['service_access']);
    await _rejects(
        services.verify(signJwt(es, _claims())), VerifierErrorCode.tokenKind);
  });

  test('bounds JWKS fetches under an unknown-kid flood (TEST-005)', () async {
    final clock = TestClock(fromSeconds(_now));
    final v = make(clock: clock);
    // Concurrent flood: one fetch, all rejected, never fail-open.
    final flood = await Future.wait(List.generate(200, (_) async {
      try {
        await v.verify(signJwt(es, _claims(), {'kid': randomHex(8)}));
        return 'accepted';
      } on VerifierException catch (e) {
        return e.code.value;
      }
    }));
    expect(flood.toSet(), {'unknown_key'});
    expect(v.fetchCount, 1);
    // Sequential flood inside the refresh interval: still no new fetches.
    for (var i = 0; i < 50; i++) {
      await _rejects(v.verify(signJwt(es, _claims(), {'kid': 'rand-$i'})),
          VerifierErrorCode.unknownKey);
    }
    expect(v.fetchCount, 1);
    // Known keys keep working during the flood.
    await v.verify(signJwt(es, _claims()));
    // After the interval, one more refresh is allowed, then the bound
    // applies again.
    clock.advance(const Duration(seconds: 61));
    for (var i = 0; i < 50; i++) {
      await _rejects(
          v.verify(
              signJwt(es, _claims({'exp': _now + 400}), {'kid': 'later-$i'})),
          VerifierErrorCode.unknownKey);
    }
    expect(v.fetchCount, 2);
  });

  test('picks up a rotated key after the refresh interval (TEST-036)',
      () async {
    final clock = TestClock(fromSeconds(_now));
    final v = make(clock: clock);
    await v.verify(signJwt(es, _claims()));
    final next = makeKey('ES256', kid: 'es-2');
    published.add(next.jwk);
    try {
      // Within the interval.
      await _rejects(
          v.verify(signJwt(next, _claims())), VerifierErrorCode.unknownKey);
      clock.advance(const Duration(seconds: 60));
      final c = await v.verify(signJwt(next, _claims({'exp': _now + 400})));
      expect(c.subject, 'usr_1');
      await v.verify(signJwt(es, _claims({'exp': _now + 400}))); // overlap
      expect(v.fetchCount, 2);
    } finally {
      published.removeLast();
    }
  });

  test('fails closed when the key set is unavailable', () async {
    final v = make();
    status = 500;
    try {
      await _rejects(
          v.verify(signJwt(es, _claims())), VerifierErrorCode.unavailable);
      // No fetch storm, still closed.
      await _rejects(
          v.verify(signJwt(es, _claims())), VerifierErrorCode.unavailable);
      expect(v.fetchCount, 1);
    } finally {
      status = 200;
    }
    final dead = make(jwksUrl: '${await deadUrl()}/jwks');
    await _rejects(
        dead.verify(signJwt(es, _claims())), VerifierErrorCode.unavailable);
  });

  test('fails closed on an invalid or oversized key set', () async {
    var body = '';
    final ks = await TestServer.start((req, _) => respondJson(req, 200, body));
    try {
      for (final b in [
        '<html>',
        '{"keys":[],"keys":[${jsonEncode(es.jwk)}]}',
        '{"keys":{}}',
        '[]',
        '{"keys":[${jsonEncode(es.jwk)}]}${' ' * (1 << 20)}',
      ]) {
        body = b;
        await _rejects(make(jwksUrl: ks.url).verify(signJwt(es, _claims())),
            VerifierErrorCode.unavailable);
      }
    } finally {
      await ks.close();
    }
  });

  test('does not follow redirects for the key set', () async {
    final redirector = await TestServer.start((req, _) async {
      req.response
        ..statusCode = 307
        ..headers.set('location', '${jwks.url}/jwks');
      await req.response.close();
    });
    try {
      await _rejects(
          make(jwksUrl: redirector.url).verify(signJwt(es, _claims())),
          VerifierErrorCode.unavailable);
      expect(redirector.hits, 1);
    } finally {
      await redirector.close();
    }
  });

  test('keeps known keys when a refresh fails', () async {
    final clock = TestClock(fromSeconds(_now));
    final v = make(clock: clock);
    await v.verify(signJwt(es, _claims()));
    status = 503;
    try {
      clock.advance(const Duration(seconds: 61));
      await _rejects(
          v.verify(
              signJwt(es, _claims({'exp': _now + 400}), {'kid': 'unknown'})),
          VerifierErrorCode.unavailable);
      await v.verify(signJwt(es, _claims({'exp': _now + 400})));
    } finally {
      status = 200;
    }
  });

  test('a cancelled caller stops waiting while the shared fetch continues',
      () async {
    final gate = Completer<void>();
    final slow = await TestServer.start((req, _) async {
      await gate.future;
      await respondJson(req, 200, {
        'keys': [es.jwk]
      });
    });
    try {
      final v = make(jwksUrl: slow.url);
      final cancel = CancelToken();
      final waiting = v.verify(signJwt(es, _claims()), cancelToken: cancel);
      final other = v.verify(signJwt(es, _claims()));
      await sleep(20);
      cancel.cancel();
      await _rejects(waiting, VerifierErrorCode.unavailable);
      gate.complete();
      expect((await other).subject, 'usr_1');
      expect(v.fetchCount, 1);
    } finally {
      if (!gate.isCompleted) gate.complete();
      await slow.close();
    }
  });

  test('skips unusable JWKS entries and ambiguous key IDs', () async {
    final enc = makeKey('ES256', kid: 'enc-1');
    final priv = makeKey('ES256', kid: 'priv-1');
    final dupA = makeKey('ES256', kid: 'dup');
    final dupB = makeKey('ES256', kid: 'dup');
    final ops = makeKey('ES256', kid: 'ops-1');
    final ks = await TestServer.start((req, _) => respondJson(req, 200, {
          'keys': [
            {...enc.jwk, 'use': 'enc'},
            priv.privateJwk,
            {'kty': 'oct', 'kid': 'hmac', 'k': b64('secret')},
            dupA.jwk,
            dupB.jwk,
            {
              ...ops.jwk,
              'key_ops': ['sign']
            },
            {
              'kty': 'RSA',
              'kid': 'weak',
              'n': b64(randomBytes(128)),
              'e': 'AQAB'
            },
            'garbage',
            {'kid': 'nokty', 'x': 'AA'},
            es.jwk,
          ],
        }));
    try {
      final v = make(jwksUrl: ks.url);
      await v.verify(signJwt(es, _claims()));
      for (final k in [enc, priv, dupA, ops]) {
        await _rejects(
            v.verify(signJwt(k, _claims())), VerifierErrorCode.unknownKey);
      }
      final tok = _hs256(
          jsonEncode({'alg': 'HS256', 'typ': 'at+jwt', 'kid': 'hmac'}),
          jsonEncode(_claims()),
          utf8.encode('secret'));
      await _rejects(v.verify(tok), VerifierErrorCode.algorithm);
    } finally {
      await ks.close();
    }
  });

  test('validates configuration', () {
    Matcher argError(String text) => throwsA(isA<ArgumentError>()
        .having((e) => '${e.message}', 'message', contains(text)));
    expect(() => Verifier(issuer: '', audience: _aud),
        argError('issuer and audience'));
    expect(() => Verifier(issuer: _iss, audience: ''),
        argError('issuer and audience'));
    expect(() => make(clockSkew: const Duration(seconds: 61)),
        argError('at most 60s'));
    expect(
        () => make(minRefreshInterval: Duration.zero), argError('at least 1s'));
    expect(() => make(jwksUrl: 'file:///etc/passwd'), argError('http'));
    expect(() => make(jwksUrl: 'https://user:pw@id.test/jwks'),
        argError('credentials'));
    expect(() => make(maxTokenBytes: 0), argError('maxTokenBytes'));
    final d = Verifier(issuer: '$_iss/', audience: _aud, httpClient: client);
    expect(d.issuer, '$_iss/');
    expect(d.audience, _aud);
  });

  test('claims helpers enforce scope and organization', () async {
    final c = await make().verify(signJwt(es, _claims()));
    expect(c.hasScope('orders:read'), isTrue);
    expect(c.hasScope('orders:delete'), isFalse);
    c.requireScopes(['orders:read', 'orders:create']);
    c.requireScope('orders:read');
    expect(() => c.requireScopes(['orders:read', 'orders:refund']),
        _code(VerifierErrorCode.scope));
    c.requireOrganization('org_a');
    expect(() => c.requireOrganization('org_b'),
        _code(VerifierErrorCode.organization));
    expect(
        () => c.requireOrganization(''), _code(VerifierErrorCode.organization));
    final noOrg = await make().verify(signJwt(es, _claims({'org_id': null})));
    expect(() => noOrg.requireOrganization(''),
        _code(VerifierErrorCode.organization));
    expect(c.isSupport, isFalse);
  });

  test('never puts token material in error messages', () async {
    final tok = signJwt(es, _claims({'aud': 'https://api.test/other'}));
    try {
      await make().verify(tok);
      fail('expected rejection');
    } on VerifierException catch (e) {
      expect(e.message, isNot(contains(tok.split('.')[1])));
      expect(e.message, isNot(contains('usr_1')));
      expect(e.message, 'verifier: wrong audience');
      expect('$e', 'verifier: wrong audience');
    }
  });

  test('error codes match the Node.js SDK categories', () {
    expect(VerifierErrorCode.values.map((c) => c.value), [
      'missing_token', 'invalid_request', 'malformed', 'too_large', //
      'duplicate_claim', 'token_type', 'algorithm', 'unknown_key', 'signature',
      'issuer', 'audience', 'expired', 'not_yet_valid', 'future_issued',
      'token_kind', 'sender_constraint', 'inactive', 'unavailable',
      'organization', 'scope',
      'support_policy', 'contract', 'stale_state', 'revoked',
    ]);
    expect(VerifierErrorCode.fromValue('stale_state'),
        VerifierErrorCode.staleState);
  });

  group('ES256 and PS256 tokens signed by Go (test/vectors/jwt.json)', () {
    final fx = jsonDecode(File('test/vectors/jwt.json').readAsStringSync())
        as Map<String, Object?>;
    late TestServer srv;
    setUpAll(() async {
      srv =
          await TestServer.start((req, _) => respondJson(req, 200, fx['jwks']));
    });
    tearDownAll(() => srv.close());
    for (final c
        in (fx['cases']! as List<Object?>).cast<Map<String, Object?>>()) {
      test('${c['name']} -> ${c['expect']}', () async {
        final v = Verifier(
          issuer: fx['issuer']! as String,
          audience: fx['audience']! as String,
          jwksUrl: srv.url,
          now: () => fromSeconds(fx['now']! as int),
          httpClient: client,
        );
        try {
          await v.verify(c['token']! as String);
          expect(c['expect'], 'accept', reason: c['why'] as String);
        } on VerifierException catch (e) {
          expect(e.code.value, c['expect'], reason: c['why'] as String);
        }
      });
    }
  });
}
