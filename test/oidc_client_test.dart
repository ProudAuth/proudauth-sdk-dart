import 'dart:convert';

import 'package:crypto/crypto.dart' show Hmac, sha256;
import 'package:http/http.dart' as http;
import 'package:proudauth_sdk/oidc_client.dart';
import 'package:test/test.dart';

import 'support/server.dart';
import 'support/signer.dart';

const _clientId = 'customer-web-bff';
const _clientSecret = 'bff-secret';
const _redirect = 'https://app.test/callback';

class _PendingCode {
  _PendingCode(this.challenge, this.nonce, this.redirectUri);
  final String challenge;
  final String nonce;
  final String redirectUri;
  bool used = false;
}

class _Rt {
  _Rt(this.family);
  final String family;
  bool used = false;
}

Matcher _oidc(OidcErrorCode code, [String? reason]) =>
    throwsA(isA<OidcException>().having((e) => e.code, 'code', code).having(
        (e) => e.reason, 'reason', reason == null ? anything : equals(reason)));

void main() {
  late TestServer idp;
  late String issuer;
  late TestKey key;
  late http.Client client;
  final clock = TestClock(
      DateTime.fromMillisecondsSinceEpoch(1800000000000, isUtc: true));
  final codes = <String, _PendingCode>{};
  // Refresh-token rotation with family revocation on reuse, like the server
  // (SES-007/008).
  final refreshTokens = <String, _Rt>{};
  final revokedFamilies = <String>{};
  final counters = {'refresh': 0, 'reuse': 0, 'code': 0, 'revoke': 0};
  ({String? auth, Map<String, String> form})? lastTokenRequest;
  ({String? auth, Map<String, String> form})? lastRevoke;
  var meta = <String, Object?>{};
  String? Function(String nonce, String at)? idTokenOverride;
  var idTokenOverrideSet = false;

  int nowSec() => clock.now.millisecondsSinceEpoch ~/ 1000;

  String idToken(Map<String, Object?> claims,
          [Map<String, Object?> header = const {'typ': 'JWT'}, TestKey? k]) =>
      signJwt(
          k ?? key,
          {
            'iss': issuer,
            'sub': 'usr_1',
            'aud': _clientId,
            'iat': nowSec(),
            'exp': nowSec() + 300,
            ...claims,
          },
          header);

  Map<String, Object?> issue(String family, [String? nonce]) {
    final at = 'pa_at_${randomHex(12)}';
    final rt = 'pa_rt_${randomHex(12)}';
    refreshTokens[rt] = _Rt(family);
    String? id;
    if (nonce != null) {
      id = idTokenOverrideSet
          ? idTokenOverride!(nonce, at)
          : idToken({
              'nonce': nonce,
              'at_hash': halfHash(key.alg, at),
              'azp': _clientId,
              'sid': 'ses_1',
              'auth_time': nowSec() - 5,
            });
    }
    return {
      'access_token': at,
      'token_type': 'Bearer',
      'expires_in': 300,
      'refresh_token': rt,
      'scope': 'openid orders:read',
      if (id != null) 'id_token': id,
    };
  }

  setUpAll(() async {
    key = makeKey('ES256', kid: 'idp-1');
    idp = await TestServer.start((req, body) async {
      final path = req.uri.path;
      const p = '/realms/main';
      if (path == '$p/.well-known/openid-configuration') {
        return respondJson(req, 200, meta);
      }
      if (path == '$p/jwks') {
        return respondJson(req, 200, {
          'keys': [key.jwk]
        });
      }
      if (path == '$p/oauth/token' && req.method == 'POST') {
        final form = Uri.splitQueryString(body);
        lastTokenRequest =
            (auth: req.headers.value('authorization'), form: form);
        if (form['grant_type'] == 'authorization_code') {
          counters['code'] = counters['code']! + 1;
          final c = codes[form['code'] ?? ''];
          if (c == null ||
              c.used ||
              pkceChallenge(form['code_verifier'] ?? '') != c.challenge ||
              form['redirect_uri'] != c.redirectUri) {
            return respondJson(req, 400, {'error': 'invalid_grant'});
          }
          c.used = true;
          return respondJson(req, 200, issue(randomHex(4), c.nonce),
              {'cache-control': 'no-store'});
        }
        if (form['grant_type'] == 'refresh_token') {
          counters['refresh'] = counters['refresh']! + 1;
          await sleep(25); // widen the race window
          final rt = refreshTokens[form['refresh_token'] ?? ''];
          if (rt == null || revokedFamilies.contains(rt.family)) {
            return respondJson(req, 400, {'error': 'invalid_grant'});
          }
          if (rt.used) {
            counters['reuse'] = counters['reuse']! + 1;
            revokedFamilies.add(rt.family); // reuse revokes the whole family
            return respondJson(req, 400, {'error': 'invalid_grant'});
          }
          rt.used = true;
          return respondJson(req, 200, issue(rt.family));
        }
        return respondJson(req, 400, {'error': 'unsupported_grant_type'});
      }
      if (path == '$p/oauth/revoke' && req.method == 'POST') {
        counters['revoke'] = counters['revoke']! + 1;
        lastRevoke = (
          auth: req.headers.value('authorization'),
          form: Uri.splitQueryString(body)
        );
        final rt = refreshTokens[lastRevoke!.form['token'] ?? ''];
        if (rt != null) revokedFamilies.add(rt.family);
        req.response.statusCode = 200;
        return req.response.close();
      }
      return respondJson(req, 404, {});
    });
    issuer = '${idp.url}/realms/main';
    client = http.Client();
  });
  tearDownAll(() async {
    client.close();
    await idp.close();
  });

  setUp(() {
    clock.now = DateTime.fromMillisecondsSinceEpoch(1800000000000, isUtc: true);
    idTokenOverride = null;
    idTokenOverrideSet = false;
    meta = {
      'issuer': issuer,
      'authorization_endpoint': '$issuer/oauth/authorize',
      'token_endpoint': '$issuer/oauth/token',
      'jwks_uri': '$issuer/jwks',
      'revocation_endpoint': '$issuer/oauth/revoke',
      'end_session_endpoint': '$issuer/oidc/logout',
      'authorization_response_iss_parameter_supported': true,
    };
  });

  OidcClient make({
    String? issuerOverride,
    String? clientSecret = _clientSecret,
    List<String>? algorithms,
    Duration clockSkew = const Duration(seconds: 30),
  }) =>
      OidcClient(
        issuer: issuerOverride ?? issuer,
        clientId: _clientId,
        clientSecret: clientSecret,
        redirectUri: _redirect,
        scopes: ['openid', 'orders:read'],
        resource: 'https://api.test/orders',
        now: clock.call,
        jwksMinRefreshInterval: const Duration(seconds: 60),
        algorithms: algorithms,
        clockSkew: clockSkew,
        httpClient: client,
      );

  /// Simulates the user completing login at the IdP: returns the callback.
  Future<({AuthRequest ar, String code, String callback})> login(
      OidcClient c) async {
    final ar = await c.authorizationUrl();
    final q = Uri.parse(ar.url).queryParameters;
    final code = 'pa_ac_${randomHex(8)}';
    codes[code] =
        _PendingCode(q['code_challenge']!, q['nonce']!, q['redirect_uri']!);
    return (
      ar: ar,
      code: code,
      callback:
          '$_redirect?code=$code&state=${ar.state}&iss=${Uri.encodeComponent(issuer)}'
    );
  }

  test('builds an authorization URL with PKCE S256, state, nonce and resource',
      () async {
    final ar = await make().authorizationUrl(extraParams: {'prompt': 'login'});
    final u = Uri.parse(ar.url);
    expect('${u.origin}${u.path}', '$issuer/oauth/authorize');
    final q = u.queryParameters;
    expect(q['response_type'], 'code');
    expect(q['client_id'], _clientId);
    expect(q['redirect_uri'], _redirect);
    expect(q['scope'], 'openid orders:read');
    expect(q['state'], ar.state);
    expect(q['nonce'], ar.nonce);
    expect(q['code_challenge_method'], 'S256');
    expect(
        q['code_challenge'],
        base64Url
            .encode(sha256.convert(utf8.encode(ar.codeVerifier)).bytes)
            .replaceAll('=', ''));
    expect(q['resource'], 'https://api.test/orders');
    expect(q['prompt'], 'login');
    expect(ar.codeVerifier.length, greaterThanOrEqualTo(43));
    expect(ar.state.length, greaterThanOrEqualTo(43));
    expect(ar.nonce.length, greaterThanOrEqualTo(43));
    expect(ar.state, isNot(ar.nonce));
    final restored = AuthRequest.fromJson(
        jsonDecode(jsonEncode(ar.toJson())) as Map<String, Object?>);
    expect(restored.codeVerifier, ar.codeVerifier);
    expect(restored.scopes, ar.scopes);
  });

  test('pkceChallenge matches RFC 7636 appendix B', () {
    expect(pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
        'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  test('refuses to override security parameters through extraParams', () async {
    for (final k in [
      'state', 'nonce', 'code_challenge', 'code_challenge_method', //
      'redirect_uri', 'client_id', 'response_type', 'scope', 'request',
    ]) {
      await expectLater(
          make().authorizationUrl(extraParams: {k: 'x'}),
          throwsA(isA<ArgumentError>().having(
              (e) => '${e.message}', 'message', contains('cannot be set'))),
          reason: k);
    }
  });

  test('exchanges the code, validating state, iss, nonce and at_hash',
      () async {
    final c = make();
    final l = await login(c);
    final r = await c.exchangeCode(l.ar, l.callback);
    expect(r.tokens.accessToken, startsWith('pa_at_'));
    expect(r.tokens.refreshToken, startsWith('pa_rt_'));
    expect(r.tokens.expiresAt, clock.now.add(const Duration(seconds: 300)));
    expect(r.idClaims?.subject, 'usr_1');
    expect(r.idClaims?.nonce, l.ar.nonce);
    expect(r.idClaims?.sid, 'ses_1');
    expect(lastTokenRequest?.form['code_verifier'], l.ar.codeVerifier);
    expect(lastTokenRequest?.form['redirect_uri'], _redirect);
    expect(lastTokenRequest?.auth,
        'Basic ${base64.encode(utf8.encode('$_clientId:$_clientSecret'))}');
    expect(lastTokenRequest?.form.containsKey('client_secret'), isFalse);
    expect('${r.tokens}', isNot(contains(r.tokens.accessToken)));
    final restored = TokenSet.fromJson(
        jsonDecode(jsonEncode(r.tokens.toJson())) as Map<String, Object?>);
    expect(restored.refreshToken, r.tokens.refreshToken);
    expect(restored.expiresAt, r.tokens.expiresAt);
  });

  test('accepts the callback as a Uri, a query string or parameter maps',
      () async {
    final c = make();
    for (final form in ['uri', 'query', 'map', 'multimap']) {
      final l = await login(c);
      final params = {'code': l.code, 'state': l.ar.state, 'iss': issuer};
      final Object callback = switch (form) {
        'uri' => Uri.parse(l.callback),
        'query' => '?${Uri(queryParameters: params).query}',
        'map' => params,
        _ => params.map((k, v) => MapEntry(k, [v])),
      };
      final r = await c.exchangeCode(l.ar, callback);
      expect(r.idClaims?.subject, 'usr_1', reason: form);
    }
    final l = await login(c);
    await expectLater(c.exchangeCode(l.ar, 42), throwsArgumentError);
  });

  test('rejects a state mismatch before redeeming the code (TEST-028)',
      () async {
    final c = make();
    final l = await login(c);
    final before = counters['code'];
    await expectLater(
        c.exchangeCode(
            l.ar, {'code': l.code, 'state': 'attacker', 'iss': issuer}),
        _oidc(OidcErrorCode.state));
    await expectLater(c.exchangeCode(l.ar, {'code': l.code, 'iss': issuer}),
        _oidc(OidcErrorCode.state));
    await expectLater(
        c.exchangeCode(l.ar,
            '?code=${l.code}&state=${l.ar.state}&state=other&iss=${Uri.encodeComponent(issuer)}'),
        _oidc(OidcErrorCode.provider));
    expect(counters['code'], before);
  });

  test(
      'rejects mix-up: wrong or missing iss in the authorization response (RFC 9207)',
      () async {
    final c = make();
    final l = await login(c);
    await expectLater(
        c.exchangeCode(l.ar,
            {'code': l.code, 'state': l.ar.state, 'iss': 'https://evil.test'}),
        _oidc(OidcErrorCode.provider));
    await expectLater(
        c.exchangeCode(l.ar, {'code': l.code, 'state': l.ar.state}),
        _oidc(OidcErrorCode.provider, 'authorization response is missing iss'));
    meta['authorization_response_iss_parameter_supported'] = false;
    final c2 = make();
    final l2 = await login(c2);
    // iss is optional when not advertised.
    await c2.exchangeCode(l2.ar, {'code': l2.code, 'state': l2.ar.state});
  });

  test('surfaces provider errors without echoing arbitrary text', () async {
    final c = make();
    final l = await login(c);
    await expectLater(
        c.exchangeCode(l.ar,
            {'error': 'access_denied', 'state': l.ar.state, 'iss': issuer}),
        throwsA(isA<OidcException>()
            .having((e) => e.code, 'code', OidcErrorCode.provider)
            .having((e) => e.providerError, 'providerError', 'access_denied')));
    await expectLater(
        c.exchangeCode(
            l.ar, {'error': '<script>', 'state': l.ar.state, 'iss': issuer}),
        throwsA(isA<OidcException>()
            .having(
                (e) => e.providerError, 'providerError', 'unrecognized_error')
            .having((e) => e.message, 'message', isNot(contains('<script>')))));
  });

  test('maps a replayed code to reauthenticate (invalid_grant)', () async {
    final c = make();
    final l = await login(c);
    await c.exchangeCode(l.ar, l.callback);
    await expectLater(
        c.exchangeCode(l.ar, l.callback), _oidc(OidcErrorCode.reauthenticate));
  });

  test('rejects a nonce mismatch and a bad at_hash', () async {
    final c = make();
    idTokenOverrideSet = true;
    idTokenOverride = (_, at) =>
        idToken({'nonce': 'other', 'at_hash': halfHash('ES256', at)});
    final l1 = await login(c);
    await expectLater(
        c.exchangeCode(l1.ar, l1.callback), _oidc(OidcErrorCode.nonce));
    idTokenOverride = (nonce, _) => idToken(
        {'nonce': nonce, 'at_hash': halfHash('ES256', 'different-token')});
    final l2 = await login(c);
    await expectLater(c.exchangeCode(l2.ar, l2.callback),
        _oidc(OidcErrorCode.idToken, 'at_hash'));
    // An openid request must return an ID token.
    idTokenOverride = (_, __) => null;
    final l3 = await login(c);
    await expectLater(c.exchangeCode(l3.ar, l3.callback),
        _oidc(OidcErrorCode.idToken, 'missing ID token'));
  });

  group('ID token validation (OIDC-016)', () {
    test('accepts a valid ID token', () async {
      final claims = await make().validateIdToken(
          idToken({
            'nonce': 'n1',
            'amr': ['pwd', 1]
          }),
          nonce: 'n1');
      expect(claims.issuer, issuer);
      expect(claims.audience, [_clientId]);
      expect(claims.amr, ['pwd']);
      expect(claims.claims['nonce'], 'n1');
    });

    test('rejects wrong issuer, audience, azp, expiry, iat, subject', () async {
      final c = make();
      Future<void> bad(String tok, String reason) => expectLater(
          c.validateIdToken(tok), _oidc(OidcErrorCode.idToken, reason));
      await bad(idToken({'iss': 'https://evil.test'}), 'issuer');
      await bad(idToken({'aud': 'other-client'}), 'audience');
      await bad(idToken({'aud': null}), 'audience');
      await bad(
          idToken({
            'aud': [_clientId, 'other']
          }),
          'authorized party');
      await c.validateIdToken(idToken({
        'aud': [_clientId, 'other'],
        'azp': _clientId
      }));
      await bad(idToken({'azp': 'other'}), 'authorized party');
      await bad(idToken({'exp': nowSec() - 31}), 'expired');
      await bad(idToken({'exp': null}), 'expired');
      await bad(idToken({'iat': nowSec() + 120}), 'issued in the future');
      await bad(idToken({'sub': ''}), 'subject');
      await bad(idToken({'sub': 5}), 'claim sub');
      await expectLater(c.validateIdToken(idToken({'nonce': 'a'}), nonce: 'b'),
          _oidc(OidcErrorCode.nonce));
      await expectLater(c.validateIdToken(idToken({}), nonce: 'b'),
          _oidc(OidcErrorCode.nonce));
      await expectLater(
          c.validateIdToken(idToken({'auth_time': nowSec() - 600}),
              maxAge: const Duration(seconds: 300)),
          _oidc(OidcErrorCode.idToken, 'max_age'));
      await expectLater(
          c.validateIdToken(idToken({}), maxAge: const Duration(seconds: 300)),
          _oidc(OidcErrorCode.idToken, 'max_age'));
      await c.validateIdToken(idToken({'auth_time': nowSec() - 100}),
          maxAge: const Duration(seconds: 300));
    });

    test('rejects alg none, HS256 confusion, access tokens and foreign keys',
        () async {
      final c = make();
      final payload = {
        'iss': issuer,
        'sub': 'usr_1',
        'aud': _clientId,
        'exp': nowSec() + 60,
      };
      final none = '${b64(jsonEncode({
            'alg': 'none',
            'kid': key.kid
          }))}.${b64(jsonEncode(payload))}.';
      await expectLater(
          c.validateIdToken(none), _oidc(OidcErrorCode.idToken, 'algorithm'));
      final input = '${b64(jsonEncode({
            'alg': 'HS256',
            'kid': key.kid
          }))}.${b64(jsonEncode(payload))}';
      final hs =
          '$input.${b64(Hmac(sha256, utf8.encode(jsonEncode(key.jwk))).convert(utf8.encode(input)).bytes)}';
      await expectLater(
          c.validateIdToken(hs), _oidc(OidcErrorCode.idToken, 'algorithm'));
      await expectLater(c.validateIdToken(idToken({}, {'typ': 'at+jwt'})),
          _oidc(OidcErrorCode.idToken, 'type'));
      await expectLater(
          c.validateIdToken(
              idToken({}, {'typ': 'JWT'}, makeKey('ES256', kid: key.kid))),
          _oidc(OidcErrorCode.idToken, 'signature'));
      final body = jsonEncode(payload);
      final dup = signRaw(key, jsonEncode({'alg': 'ES256', 'kid': key.kid}),
          '${body.substring(0, body.length - 1)},"sub":"usr_admin"}');
      await expectLater(c.validateIdToken(dup),
          _oidc(OidcErrorCode.idToken, 'duplicate member'));
      await expectLater(
          c.validateIdToken(idToken({}, {
            'typ': 'JWT',
            'crit': ['x']
          })),
          _oidc(OidcErrorCode.idToken, 'critical header'));
      await expectLater(
          c.validateIdToken(''), _oidc(OidcErrorCode.idToken, 'size'));
      await expectLater(
          c.validateIdToken('a.b'), _oidc(OidcErrorCode.idToken, 'malformed'));
    });

    test('bounds JWKS fetches for unknown key IDs', () async {
      final c = make();
      final results = await Future.wait(List.generate(100, (_) async {
        try {
          await c.validateIdToken(
              idToken({}, {'typ': 'JWT', 'kid': randomHex(6)}));
          return 'accepted';
        } on OidcException catch (e) {
          return e.code.value;
        }
      }));
      expect(results.toSet(), {'id_token'});
      expect(c.jwksFetchCount, 1);
    });
  });

  group('Session single-flight refresh (SES-009, TEST-030)', () {
    Future<({OidcClient c, Session s, TokenSet tokens, List<String> persisted})>
        loggedIn() async {
      final c = make();
      final l = await login(c);
      final r = await c.exchangeCode(l.ar, l.callback);
      final persisted = <String>[];
      final s = c.session(r.tokens,
          idClaims: r.idClaims,
          onRefresh: (t) => persisted.add(t.refreshToken!));
      return (c: c, s: s, tokens: r.tokens, persisted: persisted);
    }

    test('returns the current token while it is fresh', () async {
      final x = await loggedIn();
      expect(await x.s.accessToken(), x.tokens.accessToken);
      expect(x.s.refreshCount, 0);
    });

    test('shares one refresh among concurrent callers and survives rotation',
        () async {
      final x = await loggedIn();
      final refreshBefore = counters['refresh']!;
      final reuseBefore = counters['reuse']!;
      clock.advance(const Duration(seconds: 290)); // inside the 15 s window
      final results =
          await Future.wait(List.generate(25, (_) => x.s.accessToken()));
      expect(results.toSet(), hasLength(1));
      expect(results.first, isNot(x.tokens.accessToken));
      expect(counters['refresh']! - refreshBefore, 1);
      expect(x.s.refreshCount, 1);
      expect(x.s.tokens?.refreshToken, isNot(x.tokens.refreshToken),
          reason: 'refresh token rotated');
      expect(x.persisted, hasLength(1));
      // A second expiry: the rotated token is used; no reuse, family intact.
      clock.advance(const Duration(seconds: 300));
      final again =
          await Future.wait(List.generate(25, (_) => x.s.accessToken()));
      expect(again.toSet(), hasLength(1));
      expect(counters['refresh']! - refreshBefore, 2);
      expect(counters['reuse']! - reuseBefore, 0);
      expect(x.s.tokens?.idToken, x.tokens.idToken,
          reason: 'ID token kept when not reissued');
    });

    test(
        'without single-flight, parallel use of one refresh token revokes the family (fixture sanity)',
        () async {
      final x = await loggedIn();
      final a = x.c.session(x.tokens);
      final b = x.c.session(x.tokens); // two sessions holding the same token
      clock.advance(const Duration(seconds: 300));
      final outcomes = await Future.wait([a, b].map((s) async {
        try {
          await s.accessToken();
          return true;
        } on OidcException {
          return false;
        }
      }));
      expect(outcomes.where((ok) => !ok), hasLength(1));
      final winner = outcomes[0] ? a : b;
      clock.advance(const Duration(seconds: 300));
      // The family was revoked after the reuse.
      await expectLater(
          winner.accessToken(), _oidc(OidcErrorCode.reauthenticate));
    });

    test('forces one refresh for a rejected access token', () async {
      final x = await loggedIn();
      final both = await Future.wait([
        x.s.accessToken(rejectedToken: x.tokens.accessToken),
        x.s.accessToken(rejectedToken: x.tokens.accessToken),
      ]);
      expect(both[0], both[1]);
      expect(both[0], isNot(x.tokens.accessToken));
      expect(x.s.refreshCount, 1);
      expect(
          await x.s.accessToken(rejectedToken: x.tokens.accessToken), both[0],
          reason: 'a stale rejection does not refresh again');
      expect(x.s.refreshCount, 1);
    });

    test('a cancelled caller stops waiting; the shared refresh completes',
        () async {
      final x = await loggedIn();
      clock.advance(const Duration(seconds: 300));
      final cancel = CancelToken();
      final waiting = x.s.accessToken(cancelToken: cancel);
      final other = x.s.accessToken();
      cancel.cancel();
      await expectLater(waiting, _oidc(OidcErrorCode.provider, 'aborted'));
      expect(await other, isNot(x.tokens.accessToken));
      expect(x.s.refreshCount, 1);
    });

    test(
        'clears the session when refresh fails: the user must authenticate again',
        () async {
      final x = await loggedIn();
      await x.c.revoke(x.tokens.refreshToken!);
      clock.advance(const Duration(seconds: 300));
      await expectLater(x.s.accessToken(), _oidc(OidcErrorCode.reauthenticate));
      expect(x.s.tokens, isNull);
      final before = counters['refresh'];
      await expectLater(x.s.accessToken(), _oidc(OidcErrorCode.reauthenticate));
      expect(counters['refresh'], before, reason: 'no further provider calls');
    });
  });

  test('revokes with client authentication and builds the logout URL',
      () async {
    final c = make();
    final l = await login(c);
    final r = await c.exchangeCode(l.ar, l.callback);
    final s = c.session(r.tokens, idClaims: r.idClaims);
    final url = Uri.parse(await c.logout(s,
        postLogoutRedirectUri: 'https://app.test/bye', state: 'st'));
    expect('${url.origin}${url.path}', '$issuer/oidc/logout');
    expect(url.queryParameters['id_token_hint'], r.tokens.idToken);
    expect(url.queryParameters['client_id'], _clientId);
    expect(url.queryParameters['post_logout_redirect_uri'],
        'https://app.test/bye');
    expect(url.queryParameters['state'], 'st');
    expect(s.tokens, isNull);
    expect(lastRevoke?.form['token'], r.tokens.refreshToken);
    expect(lastRevoke?.form['token_type_hint'], 'refresh_token');
    expect(lastRevoke?.auth, startsWith('Basic '));
  });

  test('reports a failed revocation', () async {
    meta['revocation_endpoint'] = '$issuer/oauth/missing';
    await expectLater(make().revoke('pa_rt_x'),
        _oidc(OidcErrorCode.provider, 'revocation failed'));
    await make().revoke(''); // no-op
  });

  test('sends client_id in the body for public clients', () async {
    final c = make(clientSecret: '');
    final l = await login(c);
    await c.exchangeCode(l.ar, l.callback);
    expect(lastTokenRequest?.auth, isNull);
    expect(lastTokenRequest?.form['client_id'], _clientId);
  });

  test(
      'trusts only discovery from the configured issuer, with endpoints on its origin',
      () async {
    meta['issuer'] = 'https://evil.test/realms/main';
    await expectLater(make().authorizationUrl(),
        _oidc(OidcErrorCode.provider, 'discovery issuer mismatch'));
    meta['issuer'] = issuer;
    meta['token_endpoint'] = 'https://evil.test/token';
    final c = make();
    final l = await login(c);
    await expectLater(
        c.exchangeCode(l.ar, l.callback),
        _oidc(OidcErrorCode.provider,
            'endpoint token_endpoint is not on the issuer origin'));
    meta['token_endpoint'] =
        '${idp.url.replaceFirst('127.0.0.1', '127.0.0.1.evil.test')}/token';
    final c2 = make();
    final l2 = await login(c2);
    await expectLater(
        c2.exchangeCode(l2.ar, l2.callback), _oidc(OidcErrorCode.provider));
    meta['token_endpoint'] = 'https://user:pw@${idp.url.substring(7)}/token';
    final c3 = make();
    final l3 = await login(c3);
    await expectLater(
        c3.exchangeCode(l3.ar, l3.callback), _oidc(OidcErrorCode.provider));
  });

  test('retries discovery after a failure', () async {
    final c = make(issuerOverride: '${await deadUrl()}/realms/main');
    await expectLater(
        c.authorizationUrl(), _oidc(OidcErrorCode.provider, 'unreachable'));
    await expectLater(
        c.authorizationUrl(), _oidc(OidcErrorCode.provider, 'unreachable'));
  });

  test('validates configuration', () {
    Matcher argError(String text) => throwsA(isA<ArgumentError>()
        .having((e) => '${e.message}', 'message', contains(text)));
    expect(() => make(issuerOverride: ''), argError('required'));
    expect(() => make(algorithms: ['HS256']), argError('not allowed'));
    expect(
        () => make(clockSkew: const Duration(seconds: 120)), argError('60s'));
    expect(() => make(issuerOverride: 'ftp://id.test'), argError('http'));
  });

  test('error messages carry categories only', () {
    final e = OidcException(OidcErrorCode.provider,
        reason: 'token endpoint error',
        providerError: 'invalid_client',
        status: 401);
    expect(e.message,
        'oidc-client: provider error (token endpoint error, invalid_client, HTTP 401)');
    expect(OidcErrorCode.values.map((c) => c.value), [
      'state',
      'id_token',
      'nonce',
      'reauthenticate',
      'provider',
      'configuration'
    ]);
  });
}
