import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:proudauth_sdk/admin.dart';
import 'package:test/test.dart';

import 'support/server.dart';

const _token = 'pa_at_admin_secret_token';

class _Seen {
  _Seen(this.method, this.path, this.headers, this.body);
  final String method;
  final String path;
  final HttpHeaders headers;
  final String body;
}

void main() {
  late TestServer api;
  late http.Client client;
  final seen = <_Seen>[];

  setUpAll(() async {
    api = await TestServer.start((req, body) async {
      seen.add(_Seen(req.method, req.uri.toString(), req.headers, body));
      final p = req.uri.path.replaceFirst('/api/v1/realms/main%20realm', '');
      if (req.headers.value('authorization') != 'Bearer $_token') {
        return respondJson(
            req, 401, {'code': 'unauthenticated', 'title': 'Unauthenticated'});
      }
      if (p == '/users' && req.method == 'GET') {
        final cursor = req.uri.queryParameters['cursor'] ?? '';
        const pages = {
          '': {
            'items': [
              {'id': 'u1'},
              {'id': 'u2'},
            ],
            'next_cursor': 'c1',
          },
          'c1': {
            'items': [
              {'id': 'u3'},
            ],
            'next_cursor': 'c2',
          },
          'c2': {
            'items': [
              {'id': 'u4'},
            ],
            'next_cursor': '',
          },
        };
        return respondJson(req, 200, pages[cursor]);
      }
      if (p == '/organizations' && req.method == 'GET') {
        return respondJson(req, 200, {
          'items': [
            {'id': 'o1'},
          ],
          'next_cursor': 'loop',
        });
      }
      if (p == '/organizations' && req.method == 'POST') {
        final input = jsonDecode(body) as Map<String, Object?>;
        return respondJson(req, 201, {'id': 'o9', ...input, 'state': 'active'});
      }
      if (p == '/clients' && req.method == 'POST') {
        return respondJson(req, 201, {
          'client': {'client_id': 'web'},
          'client_secret': 'pa_cs_once',
          'recovery_codes': ['aaaa-bbbb'],
        }, {
          'deprecation': '@1767225600',
          'sunset': 'Wed, 01 Jul 2026 00:00:00 GMT',
        });
      }
      if (p == '/users' && req.method == 'POST') {
        final input = jsonDecode(body) as Map<String, Object?>;
        if (input['email'] == 'dup@example.test') {
          return respondJson(req, 409, {
            'type': 'https://proudauth.com/problems/conflict',
            'code': 'conflict',
            'title': 'Conflict',
            'detail': 'identifier already in use',
            'errors': {'email': 'taken'},
            'request_id': 'req_1',
            'retryable': false,
          }, {
            'content-type': 'application/problem+json'
          });
        }
        return respondJson(
            req, 201, {'id': 'u9', 'setup_token': 'pa_inv_once'});
      }
      if (p == '/users/u%2F1' && req.method == 'GET') {
        return respondJson(
            req, 200, {'id': 'u/1', 'version': 3}, {'etag': '"v3"'});
      }
      if (p == '/users/u%2F1' && req.method == 'PATCH') {
        if (req.headers.value('if-match') != '"v3"') {
          return respondJson(
              req, 412, {'code': 'precondition_failed', 'title': 'Stale'});
        }
        return respondJson(
            req, 200, {'id': 'u/1', 'version': 4}, {'etag': '"v4"'});
      }
      if (p == '/users/u1/revoke-sessions') {
        return respondJson(req, 200, {'revoked_sessions': 3});
      }
      if (p == '/users/u1/suspend') return respondJson(req, 200, {});
      if (p == '/organizations/o1/invitations/batch' && req.method == 'POST') {
        return respondJson(req, 200, {
          'results': [
            {'index': 0, 'status': 201},
          ],
        });
      }
      if (p == '/organizations/o1/members') {
        return respondJson(req, 200, {
          'items': [
            {
              'id': 'm1',
              'user_id': 'u1',
              'state': 'active',
              'roles': ['admin']
            },
          ],
          'next_cursor': '',
        });
      }
      if (p == '/roles') {
        return respondJson(req, 200, {
          'items': [
            {
              'id': 'r1',
              'name': 'viewer',
              'boundary_type': 'organization',
              'permissions': ['orders.read']
            },
          ],
        });
      }
      if (p == '/slow') {
        await sleep(500);
        return respondJson(req, 200, {});
      }
      if (p == '/empty') {
        req.response.statusCode = 204;
        return req.response.close();
      }
      if (p == '/teapot') {
        req.response.statusCode = 503;
        req.response.write('upstream exploded');
        return req.response.close();
      }
      if (p == '/notjson') return respondJson(req, 200, '<html>');
      if (p == '/redirect') {
        req.response
          ..statusCode = 302
          ..headers.set('location', 'https://evil.test/');
        return req.response.close();
      }
      if (p == '/big') return respondJson(req, 200, {'pad': 'x' * 4096});
      return respondJson(req, 404, {'code': 'not_found', 'title': 'Not Found'});
    });
    client = http.Client();
  });
  tearDownAll(() async {
    client.close();
    await api.close();
  });

  AdminClient admin({
    String? token = _token,
    TokenSource? tokenSource,
    Duration timeout = const Duration(seconds: 30),
    int maxResponseBytes = 32 << 20,
    void Function(DeprecationNotice)? onDeprecated,
    String userAgent = 'sdk-test',
  }) =>
      AdminClient(
        baseUrl: '${api.url}/',
        realm: 'main realm',
        token: tokenSource == null ? token : null,
        tokenSource: tokenSource,
        userAgent: userAgent,
        timeout: timeout,
        maxResponseBytes: maxResponseBytes,
        onDeprecated: onDeprecated,
        httpClient: client,
      );

  test('iterates every page with opaque cursors', () async {
    final ids = await admin().users('ann').map((u) => u.id).toList();
    expect(ids, ['u1', 'u2', 'u3', 'u4']);
    final paths =
        seen.where((s) => s.path.contains('/users?')).map((s) => s.path);
    expect(paths.any((p) => p.endsWith('/users?q=ann&cursor=c2')), isTrue);
    final pages = await admin()
        .pages('/users?q=ann', (e) => (e! as Map<String, Object?>)['id'])
        .toList();
    expect(pages.map((p) => p.nextCursor), ['c1', 'c2', '']);
  });

  test('stops on a cursor loop instead of spinning', () async {
    await expectLater(
        admin().organizations().toList(),
        throwsA(isA<AdminRequestException>()
            .having((e) => e.code, 'code', AdminErrorCode.invalidResponse)));
  });

  test('returns typed RFC 9457 problems', () async {
    await expectLater(
        admin().createUser({'email': 'dup@example.test'}),
        throwsA(isA<ProblemException>()
            .having((e) => e.status, 'status', 409)
            .having((e) => e.code, 'code', 'conflict')
            .having((e) => e.title, 'title', 'Conflict')
            .having((e) => e.detail, 'detail', 'identifier already in use')
            .having((e) => e.type, 'type',
                'https://proudauth.com/problems/conflict')
            .having((e) => e.errors, 'errors', {'email': 'taken'})
            .having((e) => e.requestId, 'requestId', 'req_1')
            .having((e) => e.extra['retryable'], 'extra.retryable', false)
            .having((e) => e.message, 'message',
                '409 conflict: Conflict (identifier already in use) [email: taken]')
            .having((e) => e.message, 'message', isNot(contains(_token)))));
    await expectLater(
        admin().request('GET', '/teapot'),
        throwsA(isA<ProblemException>()
            .having((e) => e.code, 'code', 'Service Unavailable')));
    await expectLater(
        admin(token: 'wrong').request('GET', '/users'),
        throwsA(
            isA<ProblemException>().having((e) => e.status, 'status', 401)));
  });

  test(
      'sends idempotency keys on creates (random by default, caller-provided for retries)',
      () async {
    await admin().createUser({'email': 'a@example.test'});
    final first = seen.last;
    expect(first.headers.value('idempotency-key'),
        matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(first.headers.value('content-type'), 'application/json');
    expect(first.headers.value('user-agent'),
        'sdk-test proudauth-sdk-dart/$sdkVersion');
    await admin().createUser({'email': 'a@example.test'},
        const RequestOptions(idempotencyKey: 'retry-key-1'));
    expect(seen.last.headers.value('idempotency-key'), 'retry-key-1');
    final org = await admin().createOrganization('acme', 'Acme');
    expect(org.slug, 'acme');
    expect(org.displayName, 'Acme');
    expect(seen.last.headers.value('idempotency-key'),
        matches(RegExp(r'^[0-9a-f]{32}$')));
  });

  test('keeps the generated idempotency key for batch invitations', () async {
    final results = await admin().inviteBatch('o1', [
      {'email': 'a@example.test'},
    ]);
    expect(results, [
      {'index': 0, 'status': 201},
    ]);
    expect(seen.last.headers.value('idempotency-key'),
        matches(RegExp(r'^[0-9a-f]{32}$')));
    await admin()
        .inviteBatch('o1', [], const RequestOptions(idempotencyKey: ''));
    expect(seen.last.headers.value('idempotency-key'),
        matches(RegExp(r'^[0-9a-f]{32}$')));
    await admin().inviteBatch(
        'o1', [], const RequestOptions(idempotencyKey: 'batch-retry-1'));
    expect(seen.last.headers.value('idempotency-key'), 'batch-retry-1');
  });

  test('supports If-Match with ETags and escapes path identifiers', () async {
    final a = admin();
    final got = await a.getUser('u/1');
    expect(got.etag, '"v3"');
    expect(got.data.id, 'u/1');
    expect(got.data.version, 3);
    final upd = await a.updateUser(
        'u/1', {'display_name': 'Ann'}, RequestOptions(ifMatch: got.etag));
    expect(upd.etag, '"v4"');
    await expectLater(
        a.updateUser('u/1', {'display_name': 'Ann'},
            const RequestOptions(ifMatch: '"v1"')),
        throwsA(
            isA<ProblemException>().having((e) => e.status, 'status', 412)));
  });

  test('typed helpers decode lists and members', () async {
    final members = await admin().members('o1').toList();
    expect(members.single.userId, 'u1');
    expect(members.single.roles, ['admin']);
    final roles = await admin().roles('organization');
    expect(roles.single.permissions, ['orders.read']);
    expect(seen.last.path, endsWith('/roles?boundary_type=organization'));
    await admin().setUserState('u1', UserStateAction.suspend, 'abuse');
    expect(seen.last.path, endsWith('/users/u1/suspend'));
    expect(jsonDecode(seen.last.body), {'reason': 'abuse'});
    await expectLater(admin().members('').toList(), throwsArgumentError);
    await expectLater(admin().getUser(''), throwsArgumentError);
  });

  test('enforces deadlines and cancellation', () async {
    await expectLater(
        admin(timeout: const Duration(milliseconds: 50))
            .request('GET', '/slow'),
        throwsA(isA<AdminRequestException>()
            .having((e) => e.code, 'code', AdminErrorCode.timeout)));
    final cancel = CancelToken();
    Timer(const Duration(milliseconds: 20), cancel.cancel);
    await expectLater(
        admin().request('GET', '/slow',
            options: RequestOptions(cancelToken: cancel)),
        throwsA(isA<AdminRequestException>()
            .having((e) => e.code, 'code', AdminErrorCode.aborted)));
    await expectLater(
        admin().request('GET', '/slow',
            options: const RequestOptions(timeout: Duration(milliseconds: 30))),
        throwsA(isA<AdminRequestException>()
            .having((e) => e.code, 'code', AdminErrorCode.timeout)));
  });

  test('uses token sources, handles empty bodies and validates input',
      () async {
    var calls = 0;
    final a = admin(tokenSource: (_) async {
      calls++;
      return _token;
    });
    expect(await a.revokeSessions('u1'), 3);
    final empty = await a.request('POST', '/empty', body: <String, Object?>{});
    expect(empty.status, 204);
    expect(empty.data, isNull);
    expect(calls, 2);
    await expectLater(
        a.request('GET', 'users'),
        throwsA(isA<ArgumentError>()
            .having((e) => '${e.message}', 'message', contains('must start'))));
    await expectLater(
        admin(tokenSource: (_) => Future.error(StateError('vault down')))
            .request('GET', '/users'),
        throwsA(isA<AdminRequestException>()
            .having((e) => e.code, 'code', AdminErrorCode.tokenSource)));
    expect(
        () => AdminClient(baseUrl: 'not a url', realm: 'r'),
        throwsA(isA<ArgumentError>().having(
            (e) => '${e.message}', 'message', contains('absolute URL'))));
    expect(() => AdminClient(baseUrl: api.url, realm: ''), throwsArgumentError);
    expect(
        () => AdminClient(
            baseUrl: api.url, realm: 'r', token: 'a', tokenSource: (_) => 'b'),
        throwsArgumentError);
  });

  test('refuses redirects, invalid JSON and oversized responses', () async {
    await expectLater(
        admin().request('GET', '/redirect'),
        throwsA(isA<AdminRequestException>()
            .having((e) => e.code, 'code', AdminErrorCode.network)));
    await expectLater(
        admin().request('GET', '/notjson'),
        throwsA(isA<AdminRequestException>()
            .having((e) => e.code, 'code', AdminErrorCode.invalidResponse)));
    await expectLater(
        admin(maxResponseBytes: 1024).request('GET', '/big'),
        throwsA(isA<AdminRequestException>()
            .having((e) => e.code, 'code', AdminErrorCode.network)));
  });

  test('never includes request bodies or tokens in transport errors', () async {
    final dead = AdminClient(
        baseUrl: await deadUrl(),
        realm: 'main',
        token: _token,
        httpClient: client);
    await expectLater(
        dead.createUser({'password': 'hunter2'}),
        throwsA(isA<AdminRequestException>()
            .having((e) => e.code, 'code', AdminErrorCode.network)
            .having((e) => e.message, 'message', isNot(contains('hunter2')))
            .having((e) => e.message, 'message', isNot(contains(_token)))
            .having((e) => e.path, 'path', '/users')));
  });

  test(
      'wraps one-time secrets, sends its version and reports deprecation (SDK-007)',
      () async {
    final notes = <String>[];
    final a = admin(
        userAgent: 'tool/1',
        onDeprecated: (d) =>
            notes.add('${d.method} ${d.path} ${d.deprecation}'));
    final res = await a.request('POST', '/clients', body: <String, Object?>{});
    final data = res.data! as Map<String, Object?>;
    final secret = data['client_secret'];
    expect(secret, isA<Secret>());
    expect((secret! as Secret).reveal(), 'pa_cs_once');
    final codes = data['recovery_codes']! as List<Object?>;
    expect(codes.single, isA<Secret>());
    final shown =
        ['$secret', jsonEncode(data), '$data', '${res.data}'].join(' ');
    expect(shown, isNot(contains('pa_cs_once')));
    expect(shown, isNot(contains('aaaa-bbbb')));
    expect(data['client'], {'client_id': 'web'});
    expect(res.deprecation, '@1767225600');
    expect(res.sunset, 'Wed, 01 Jul 2026 00:00:00 GMT');
    expect(notes, ['POST /clients @1767225600']);
    final sent = seen.last.headers;
    expect(sent.value('proudauth-sdk'), 'dart/$sdkVersion');
    expect(sent.value('user-agent'), 'tool/1 proudauth-sdk-dart/$sdkVersion');
    final created = await a.createUser({'email': 'b@example.test'});
    expect(created['setup_token'], isA<Secret>());
    expect(const Secret('').toString(), '');
  });

  test('sdkVersion matches pubspec.yaml', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    expect(RegExp(r'^version: (\S+)$', multiLine: true).firstMatch(pubspec)?[1],
        sdkVersion);
  });
}
