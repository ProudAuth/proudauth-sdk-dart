import 'package:http/http.dart' as http;
import 'package:proudauth_sdk/verifier.dart';
import 'package:test/test.dart';

import 'support/server.dart';
import 'support/signer.dart';

const _aud = 'https://api.test/orders';

class _Issuer {
  _Issuer(this.url, this.key);
  final String url;
  final TestKey key;
  late TestServer jwks;
}

void main() {
  final issuers = [
    _Issuer('https://id.test/realms/acme', makeKey('ES256', kid: 'a1')),
    _Issuer('https://id.test/realms/globex', makeKey('ES256', kid: 'b1')),
    _Issuer('https://rogue.test', makeKey('ES256', kid: 'r1')),
  ];
  final client = http.Client();

  setUpAll(() async {
    for (final i in issuers) {
      i.jwks = await TestServer.start((req, _) => respondJson(req, 200, {
            'keys': [i.key.jwk]
          }));
    }
  });
  tearDownAll(() async {
    client.close();
    for (final i in issuers) {
      await i.jwks.close();
    }
  });

  String token(_Issuer i) {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return signJwt(i.key, {
      'iss': i.url,
      'sub': 'usr_same',
      'aud': _aud,
      'client_id': 'web',
      'iat': now,
      'exp': now + 300,
      'jti': 'j',
      'scope': 'orders:read',
      'token_kind': 'user_access',
    });
  }

  Verifier verifier(_Issuer i) => Verifier(
      issuer: i.url, audience: _aud, jwksUrl: i.jwks.url, httpClient: client);

  test(
      'verifies registered issuers with their tenant and refuses others (INT-009)',
      () async {
    final [a, b, rogue] = issuers;
    final m = MultiIssuerVerifier({
      a.url: IssuerRegistration(verifier: verifier(a), tenant: 'acme'),
      b.url: IssuerRegistration(verifier: verifier(b), tenant: 'globex'),
    });
    final ta = await m.verifyTenant(token(a));
    expect(ta.tenant, 'acme');
    expect(ta.claims.subject, 'usr_same');
    expect((await m.verifyTenant(token(b))).tenant, 'globex');
    expect((await m.authenticate(token(b))).issuer, b.url);
    await expectLater(
        m.verifyTenant(token(rogue)),
        throwsA(isA<VerifierException>()
            .having((e) => e.code, 'code', VerifierErrorCode.issuer)));
    expect(rogue.jwks.hits, 0,
        reason: 'unregistered issuers are never fetched');
    for (final bad in ['not-a-jwt', 'a.b.c', 'a.${'e30'}.c', '']) {
      await expectLater(
          m.authenticate(bad),
          throwsA(isA<VerifierException>()
              .having((e) => e.code, 'code', VerifierErrorCode.malformed)),
          reason: bad);
    }
    expect(
        () => MultiIssuerVerifier({
              b.url: IssuerRegistration(verifier: verifier(a), tenant: 'x'),
            }),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message',
            contains('exactly that issuer'))));
    expect(() => MultiIssuerVerifier({}), throwsArgumentError);
  });

  test('a token for one tenant does not pass as another tenant', () async {
    final [a, b, _] = issuers;
    // b's key signs a token claiming a's issuer: a's verifier refuses it.
    final forged = signJwt(b.key.withKid(a.key.kid), {
      'iss': a.url,
      'sub': 'usr_same',
      'aud': _aud,
      'client_id': 'web',
      'exp': DateTime.now().millisecondsSinceEpoch ~/ 1000 + 300,
      'jti': 'j',
      'token_kind': 'user_access',
    });
    final m = MultiIssuerVerifier({
      a.url: IssuerRegistration(verifier: verifier(a), tenant: 'acme'),
      b.url: IssuerRegistration(verifier: verifier(b), tenant: 'globex'),
    });
    await expectLater(
        m.verifyTenant(forged),
        throwsA(isA<VerifierException>()
            .having((e) => e.code, 'code', VerifierErrorCode.signature)));
  });
}
