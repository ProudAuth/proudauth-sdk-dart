// Shared verification fixtures (SDK-009): the same accepted and rejected
// tokens the Go and Node.js SDKs check, so every SDK agrees on every
// outcome. The fixtures live at testdata/contracts in this standalone repository and are only
// read here.
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:proudauth_sdk/verifier.dart';
import 'package:test/test.dart';

import 'support/server.dart';

final Map<String, Object?> _fx = jsonDecode(
        File('testdata/contracts/access-tokens/cases.json').readAsStringSync())
    as Map<String, Object?>;

void main() {
  final cases = (_fx['cases']! as List<Object?>).cast<Map<String, Object?>>();
  late TestServer srv;
  late http.Client client;
  late Verifier verifier;

  setUpAll(() async {
    srv =
        await TestServer.start((req, _) => respondJson(req, 200, _fx['jwks']));
    client = http.Client();
    verifier = Verifier(
      issuer: _fx['issuer']! as String,
      audience: _fx['audience']! as String,
      jwksUrl: '${srv.url}/jwks',
      now: () => fromSeconds(_fx['now']! as int),
      minRefreshInterval: const Duration(seconds: 1),
      httpClient: client,
    );
  });
  tearDownAll(() async {
    client.close();
    await srv.close();
  });

  test('the fixture file has the 22 shared cases', () {
    expect(cases, hasLength(22));
    expect(cases.where((c) => c['expect'] == 'accept'), hasLength(2));
  });

  group('access-tokens/cases.json', () {
    for (final c in cases) {
      test('${c['name']} -> ${c['expect']}', () async {
        try {
          final claims = await verifier.verify(c['token']! as String);
          expect(c['expect'], 'accept',
              reason:
                  '${c['name']}: accepted, want ${c['expect']} (${c['why']})');
          expect(claims.issuer, _fx['issuer']);
          expect(claims.audience, _fx['audience']);
        } on VerifierException catch (e) {
          expect(e.code.value, c['expect'],
              reason:
                  '${c['name']}: got ${e.code.value}, want ${c['expect']} (${c['why']})');
        }
      });
    }
  });
}
