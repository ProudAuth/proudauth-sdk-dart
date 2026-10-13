import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:proudauth_sdk/io.dart';
import 'package:proudauth_sdk/verifier.dart';
import 'package:test/test.dart';

import 'support/server.dart';
import 'support/signer.dart';

const _iss = 'https://id.test/realms/main';
const _aud = 'https://api.test/orders';

String _token(TestKey key, [Map<String, Object?> extra = const {}]) {
  final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  return signJwt(key, {
    'iss': _iss,
    'sub': 'usr_1',
    'aud': _aud,
    'client_id': 'web',
    'iat': now,
    'exp': now + 300,
    'jti': 'j1',
    'scope': 'orders:read',
    'org_id': 'org_a',
    'token_kind': 'user_access',
    ...extra,
  });
}

Matcher _code(VerifierErrorCode code) =>
    throwsA(isA<VerifierException>().having((e) => e.code, 'code', code));

class _Stub implements Authenticator {
  _Stub(this.result);
  final Object result; // Claims or an error to throw
  @override
  Future<Claims> authenticate(String raw, {CancelToken? cancelToken}) async {
    final r = result;
    if (r is Claims) return r;
    throw r;
  }
}

Claims _claims({List<String> scopes = const ['orders:read']}) => Claims(
      issuer: _iss,
      subject: 'usr_1',
      audience: _aud,
      clientId: 'web',
      scopes: scopes,
      orgId: 'org_a',
      sessionId: '',
      tokenKind: 'user_access',
      jti: 'j',
      acr: '',
      authzVersion: 0,
      online: false,
    );

void main() {
  group('bearerToken', () {
    test('extracts a bearer token from the Authorization header only', () {
      expect(bearerToken('Bearer abc.def.ghi'), 'abc.def.ghi');
      expect(bearerToken('bearer   pa_it_x-y_z  '), 'pa_it_x-y_z');
      expect(
          bearerToken('BEARER t', requestUri: Uri.parse('/orders?x=1')), 't');
      expect(bearerTokenFromValues(['Bearer t']), 't');
    });

    test(
        'refuses access tokens in the query string, even with a header (TOK-023)',
        () {
      for (final url in [
        '/orders?access_token=abc',
        '/orders?a=1&access_token=abc',
        '/orders?access%5Ftoken=abc',
      ]) {
        expect(() => bearerToken('Bearer abc', requestUri: Uri.parse(url)),
            _code(VerifierErrorCode.invalidRequest),
            reason: url);
      }
      expect(
          () => bearerToken(null,
              requestUri: Uri.parse('/api/x?access_token=abc')),
          _code(VerifierErrorCode.invalidRequest));
    });

    test('reports missing, repeated and malformed credentials', () {
      final missing = _code(VerifierErrorCode.missingToken);
      expect(() => bearerToken(null), missing);
      expect(() => bearerToken('Basic dXNlcjpwYXNz'), missing);
      expect(() => bearerToken('Bearer '), missing);
      expect(() => bearerToken('Bearer    '), missing);
      expect(() => bearerTokenFromValues([]), missing);
      expect(() => bearerTokenFromValues(['Bearer a', 'Bearer b']),
          _code(VerifierErrorCode.invalidRequest));
      expect(
          () => bearerToken('Bearer a b'), _code(VerifierErrorCode.malformed));
      expect(
          () => bearerToken('Bearer a,b'), _code(VerifierErrorCode.malformed));
    });
  });

  group('challenge', () {
    test('maps error categories to RFC 6750 responses', () {
      final missing =
          challenge(VerifierException(VerifierErrorCode.missingToken));
      expect(missing.status, 401);
      expect(missing.headers, {'www-authenticate': 'Bearer'});
      expect(missing.error, isNull);
      expect(
          challenge(VerifierException(VerifierErrorCode.missingToken),
                  realm: 'orders "api"')
              .headers,
          {'www-authenticate': r'Bearer realm="orders \"api\""'});
      expect(challenge(VerifierException(VerifierErrorCode.expired)).headers,
          {'www-authenticate': 'Bearer error="invalid_token"'});
      expect(
          challenge(VerifierException(VerifierErrorCode.invalidRequest)).status,
          400);
      final scope = challenge(VerifierException(VerifierErrorCode.scope),
          scopes: ['orders:write']);
      expect(scope.status, 403);
      expect(scope.headers['www-authenticate'],
          'Bearer error="insufficient_scope", scope="orders:write"');
      final org = challenge(VerifierException(VerifierErrorCode.organization));
      expect(org.status, 403);
      expect(org.headers,
          {'www-authenticate': 'Bearer error="insufficient_scope"'});
      expect(org.error, 'insufficient_scope');
      final policy =
          challenge(VerifierException(VerifierErrorCode.supportPolicy));
      expect([policy.status, policy.headers], [403, <String, String>{}]);
      for (final c in [
        VerifierErrorCode.unavailable,
        VerifierErrorCode.staleState
      ]) {
        final ch = challenge(VerifierException(c));
        expect([ch.status, ch.headers], [503, <String, String>{}]);
      }
      expect(
          challenge(VerifierException(VerifierErrorCode.contract)).status, 500);
      expect(challenge(StateError('boom')).status, 500);
      expect(missing.responseHeaders['cache-control'], 'no-store');
      expect(missing.body, 'Unauthorized');
      expect(
          challenge(VerifierException(VerifierErrorCode.missingToken),
                  realm: 'a\r\nb')
              .headers['www-authenticate'],
          'Bearer realm="a  b"');
    });
  });

  group('authorizeBearer (framework-neutral)', () {
    test('returns claims, or a challenge for every failure', () async {
      final ok = await authorizeBearer(_Stub(_claims()),
          authorization: 'Bearer abc', requiredScopes: ['orders:read']);
      expect(ok, isA<AuthAccepted>());
      expect((ok as AuthAccepted).claims.subject, 'usr_1');

      final errors = <Object>[];
      final noScope = await authorizeBearer(_Stub(_claims()),
          authorization: 'Bearer abc',
          requiredScopes: ['orders:write'],
          onError: errors.add);
      expect(noScope, isA<AuthRejected>());
      final ch = (noScope as AuthRejected).challenge;
      expect(ch.status, 403);
      expect(ch.headers['www-authenticate'],
          'Bearer error="insufficient_scope", scope="orders:write"');

      final expired = await authorizeBearer(
          _Stub(VerifierException(VerifierErrorCode.expired)),
          authorization: 'Bearer abc',
          realm: 'orders',
          onError: (e) => throw StateError('telemetry must not matter'));
      expect((expired as AuthRejected).challenge.headers['www-authenticate'],
          'Bearer realm="orders", error="invalid_token"');

      final missing = await authorizeBearer(_Stub(_claims()));
      expect((missing as AuthRejected).challenge.status, 401);
      final inQuery = await authorizeBearer(_Stub(_claims()),
          authorization: 'Bearer abc',
          requestUri: Uri.parse('/x?access_token=abc'),
          onError: errors.add);
      expect((inQuery as AuthRejected).challenge.status, 400);
      final crash = await authorizeBearer(_Stub(StateError('bug')),
          authorization: 'Bearer abc');
      expect((crash as AuthRejected).challenge.status, 500);
      expect(errors.map((e) => (e as VerifierException).code),
          [VerifierErrorCode.scope, VerifierErrorCode.invalidRequest]);
    });

    test('authenticateAuthorization extracts and verifies', () async {
      final c = await authenticateAuthorization(_Stub(_claims()), 'Bearer abc');
      expect(c.subject, 'usr_1');
      await expectLater(authenticateAuthorization(_Stub(_claims()), 'Basic x'),
          _code(VerifierErrorCode.missingToken));
    });
  });

  group('dart:io adapter', () {
    late TestKey key;
    late TestServer jwks;
    var jwksUp = true;
    late HttpServer api;
    late String base;
    late http.Client client;
    String? seenSubject;
    final errors = <String>[];

    setUpAll(() async {
      key = makeKey('ES256', kid: 'k1');
      jwks = await TestServer.start((req, _) => jwksUp
          ? respondJson(req, 200, {
              'keys': [key.jwk]
            })
          : respondJson(req, 500, {}));
      client = http.Client();
      final verifier = Verifier(
          issuer: _iss,
          audience: _aud,
          jwksUrl: jwks.url,
          minRefreshInterval: const Duration(seconds: 1),
          httpClient: client);
      final orders = protect(verifier, (req, claims) {
        seenSubject = claimsOf(req)?.subject;
        req.response.write('ok:${claims.subject}');
        return req.response.close();
      },
          onError: (e, _) =>
              errors.add(e is VerifierException ? e.code.value : 'other'));
      final write = protect(verifier, (req, claims) {
        req.response.write('wrote');
        return req.response.close();
      }, requiredScopes: ['orders:write']);
      final crash = protect(verifier, (req, claims) => throw StateError('bug'));
      api = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      api.listen((req) {
        final path = req.uri.path;
        final handler = path.startsWith('/write')
            ? write
            : path.startsWith('/crash')
                ? crash
                : orders;
        handler(req);
      });
      base = 'http://127.0.0.1:${api.port}';
    });
    tearDownAll(() async {
      client.close();
      await api.close(force: true);
      await jwks.close();
    });

    Future<http.Response> call(String path, [String? auth]) =>
        client.get(Uri.parse('$base$path'),
            headers: auth == null ? {} : {'authorization': auth});

    test('passes verified claims to the handler', () async {
      final res = await call('/orders', 'Bearer ${_token(key)}');
      expect(res.statusCode, 200);
      expect(res.body, 'ok:usr_1');
      expect(seenSubject, 'usr_1');
    });

    test('challenges a missing token without an error code', () async {
      final res = await call('/orders');
      expect(res.statusCode, 401);
      expect(res.headers['www-authenticate'], 'Bearer');
      expect(res.headers['cache-control'], 'no-store');
    });

    test('rejects invalid tokens with invalid_token and never runs the handler',
        () async {
      seenSubject = null;
      final idToken = signJwt(key, {
        'iss': _iss,
        'sub': 'usr_1',
        'aud': _aud,
        'exp': DateTime.now().millisecondsSinceEpoch ~/ 1000 + 60,
      }, {
        'typ': 'JWT'
      });
      for (final t in [
        _token(key, {'aud': 'https://api.test/billing'}),
        idToken,
        'not-a-jwt',
      ]) {
        final res = await call('/orders', 'Bearer $t');
        expect(res.statusCode, 401);
        expect(res.headers['www-authenticate'], 'Bearer error="invalid_token"');
        expect(res.body, isNot(contains(t)));
      }
      expect(seenSubject, isNull);
      expect(errors, containsAll(['audience', 'token_type']));
    });

    test('answers 400 invalid_request for a query-string token', () async {
      final res = await call('/orders?access_token=${_token(key)}');
      expect(res.statusCode, 400);
      expect(res.headers['www-authenticate'], 'Bearer error="invalid_request"');
    });

    test('enforces scopes with 403 insufficient_scope', () async {
      final denied = await call('/write', 'Bearer ${_token(key)}');
      expect(denied.statusCode, 403);
      expect(denied.headers['www-authenticate'],
          'Bearer error="insufficient_scope", scope="orders:write"');
      final ok = await call('/write',
          'Bearer ${_token(key, {'scope': 'orders:read orders:write'})}');
      expect(ok.statusCode, 200);
      expect(ok.body, 'wrote');
    });

    test('answers 500 when the handler throws', () async {
      final res = await call('/crash', 'Bearer ${_token(key)}');
      expect(res.statusCode, 500);
    });

    test('answers 503 (fail closed) when keys cannot be loaded', () async {
      jwksUp = false;
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      try {
        final verifier = Verifier(
            issuer: _iss,
            audience: _aud,
            jwksUrl: jwks.url,
            httpClient: client);
        final handler = protect(verifier, (req, _) {
          req.response.write('should not run');
          return req.response.close();
        });
        server.listen(handler);
        final res = await client.get(
            Uri.parse('http://127.0.0.1:${server.port}/'),
            headers: {'authorization': 'Bearer ${_token(key)}'});
        expect(res.statusCode, 503);
        expect(res.headers['www-authenticate'], isNull);
        expect(res.body, 'Service Unavailable');
      } finally {
        jwksUp = true;
        await server.close(force: true);
      }
    });

    test('authenticateHttpRequest reads every Authorization header', () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final results = <String>[];
      server.listen((req) async {
        try {
          final c = await authenticateHttpRequest(_Stub(_claims()), req);
          results.add(c.subject);
        } on VerifierException catch (e) {
          results.add(e.code.value);
        }
        await req.response.close();
      });
      try {
        final socket = await Socket.connect('127.0.0.1', server.port);
        socket.write('GET / HTTP/1.1\r\nHost: x\r\n'
            'Authorization: Bearer a\r\nAuthorization: Bearer b\r\n'
            'Connection: close\r\n\r\n');
        await socket.flush();
        await socket.drain<void>();
        await socket.close();
        await client.get(Uri.parse('http://127.0.0.1:${server.port}/'),
            headers: {'authorization': 'Bearer t'});
        expect(results, ['invalid_request', 'usr_1']);
      } finally {
        await server.close(force: true);
      }
    });
  });
}
