// The support-operation table is shared with the Go and Node.js SDKs and the
// server (sdk/fixtures/support-operations/cases.json), so every guard
// classifies every operation identically. Read only.
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:proudauth_sdk/introspection.dart';
import 'package:test/test.dart';

import 'support/server.dart';

const _iss = 'https://id.test/realms/main';
const _aud = 'https://api.test/orders';

final Map<String, Object?> _fx = jsonDecode(
    File('testdata/contracts/support-operations/cases.json')
        .readAsStringSync()) as Map<String, Object?>;

List<Map<String, Object?>> _list(String k) =>
    (_fx[k]! as List<Object?>).cast<Map<String, Object?>>();

void main() {
  late TestServer idp;
  late http.Client client;

  setUpAll(() async {
    // The token is echoed as the support mode.
    idp = await TestServer.start((req, body) {
      final mode = Uri.splitQueryString(body)['token'] ?? '';
      return respondJson(req, 200, {
        'active': true,
        'iss': _iss,
        'aud': _aud,
        'sub': 'usr_customer',
        'client_id': 'support-bff',
        'token_kind': 'impersonation_access',
        'act': {'sub': 'usr_agent'},
        'impersonation_grant_id': 'imp_1',
        'support_mode': mode,
        'jti': 'tok_support_1',
        'org_id': 'org_a',
      });
    });
    client = http.Client();
  });
  tearDownAll(() async {
    client.close();
    await idp.close();
  });

  Introspector introspector() => Introspector(
        endpoint: '${idp.url}/oauth/introspect',
        clientId: 'rs',
        clientSecret: 's',
        issuer: _iss,
        audience: _aud,
        httpClient: client,
      );

  final writeOps = (_fx['write_operations']! as List<Object?>).cast<String>();

  test('classifies every operation like the Go and Node.js SDKs', () {
    final all = [..._list('classification_only'), ..._list('cases')];
    expect(_list('cases'), isNotEmpty);
    for (final c in all) {
      final op = c['operation']! as String;
      expect(isProtectedOperation(op), c['protected'],
          reason: 'isProtectedOperation(${jsonEncode(op)}): ${c['why']}');
      expect(isWriteOperation(op), c['write'],
          reason: 'isWriteOperation(${jsonEncode(op)}): ${c['why']}');
    }
  });

  group('SupportGuard decisions', () {
    for (final c in _list('cases')) {
      final op = c['operation']! as String;
      final read = c['read']! as bool;
      final mode = c['support_mode']! as String;
      final expected = c['expect']! as String;
      final label = '$op read=$read $mode: ${c['why']}';
      test('$op read=$read $mode -> $expected', () async {
        final events = <SupportEvent>[];
        final guard = SupportGuard(
          introspector: introspector(),
          auditor: SupportAuditor.from((ev, _) => events.add(ev)),
          writeOperations: writeOps,
        );
        if (expected == 'allow') {
          await guard.authorize(mode, op, read: read);
        } else {
          await expectLater(
            guard.authorize(mode, op, read: read),
            throwsA(isA<VerifierException>().having(
                (e) => e.code, 'code', VerifierErrorCode.supportPolicy)),
            reason: label,
          );
        }
        expect(events, hasLength(1), reason: label);
        final ev = events.single;
        expect(ev.allowed, expected == 'allow', reason: label);
        expect(ev.denyReason?.value, expected == 'allow' ? null : expected,
            reason: label);
        expect(ev.read, read && !(c['write']! as bool), reason: label);
        expect(ev.actor, 'usr_agent', reason: label);
      });
    }
  });

  test('denies an empty operation without auditing', () async {
    final events = <SupportEvent>[];
    final guard = SupportGuard(
      introspector: introspector(),
      auditor: SupportAuditor.from((ev, _) => events.add(ev)),
    );
    await expectLater(
      guard.authorize('read_only', '  ', read: true),
      throwsA(isA<VerifierException>()
          .having((e) => e.code, 'code', VerifierErrorCode.supportPolicy)),
    );
    expect(events, isEmpty);
  });
}
