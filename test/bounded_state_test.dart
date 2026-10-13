import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:proudauth_sdk/bounded_state.dart';
import 'package:proudauth_sdk/verifier.dart' show challenge;
import 'package:test/test.dart';

import 'support/server.dart';

Claims _claims(String subject, String sessionId, DateTime issuedAt,
        [String orgId = 'org_1']) =>
    Claims(
      issuer: 'https://id.test/realms/main',
      subject: subject,
      audience: 'https://api.test',
      clientId: 'web',
      scopes: const [],
      orgId: orgId,
      sessionId: sessionId,
      tokenKind: 'user_access',
      jti: 'j',
      issuedAt: issuedAt,
      acr: '',
      authzVersion: 0,
      online: false,
    );

Matcher _code(VerifierErrorCode code) =>
    throwsA(isA<VerifierException>().having((e) => e.code, 'code', code));

String _iso(DateTime t) => t.toUtc().toIso8601String();

Map<String, Object?> _revoked(String sessionId, DateTime at) => {
      'event_type': 'session.revoked',
      'occurred_at': _iso(at),
      'data': {'session_id': sessionId},
    };

/// A fake stream: [handle] answers (status, body) for a cursor ('now' for
/// from=now).
({http.Client client, List<String> cursors}) _fakeStream(
    (int, Object?) Function(String cursor) handle) {
  final cursors = <String>[];
  final client = MockClient((req) async {
    final q = req.url.queryParameters;
    final cursor = q['from'] == 'now' ? 'now' : (q['cursor'] ?? '');
    cursors.add(cursor);
    // Yield to the event loop like a real request.
    await Future<void>.delayed(Duration.zero);
    final (status, body) = handle(cursor);
    return http.Response(jsonEncode(body), status,
        headers: {'content-type': 'application/json'});
  });
  return (client: client, cursors: cursors);
}

void main() {
  group('bounded-state verification (SDK-002)', () {
    late TestServer idp;
    late http.Client client;
    var pending = <Object?>[];
    var auth = '';
    final clock = TestClock(DateTime.utc(2026, 10, 10, 10));

    setUpAll(() async {
      idp = await TestServer.start((req, _) {
        auth = req.headers.value('authorization') ?? '';
        if (req.uri.path != '/api/v1/realms/main/session-events') {
          return respondJson(req, 404, {});
        }
        if (req.uri.queryParameters['from'] == 'now') {
          return respondJson(
              req, 200, {'events': <Object?>[], 'next_cursor': '10.0'});
        }
        final events = pending;
        pending = [];
        return respondJson(req, 200, {'events': events, 'next_cursor': '11.0'});
      });
      client = http.Client();
    });
    tearDownAll(() async {
      client.close();
      await idp.close();
    });

    BoundedState state() => BoundedState(
          baseUrl: idp.url,
          realm: 'main',
          token: () async => 'svc-token',
          maxStaleness: const Duration(seconds: 60),
          now: clock.call,
          httpClient: client,
        );

    test('rejects revoked sessions and subjects and fails closed when stale',
        () async {
      final s = state();
      final now = clock.now;
      await s.start();
      expect(auth, 'Bearer svc-token');
      final t0 = now.subtract(const Duration(seconds: 1));
      s.check(_claims('usr_bob', 'ses_1', t0));
      pending = [
        {
          'event_type': 'session.revoked',
          'occurred_at': _iso(now),
          'data': {'user_id': 'usr_bob', 'session_id': 'ses_1'},
        },
        {
          'event_type': 'user.suspended',
          'occurred_at': _iso(now),
          'data': {'user_id': 'usr_carol'},
        },
        {
          'event_type': 'user.recovery_restricted',
          'occurred_at': _iso(now),
          'data': {'user_id': 'usr_dave'},
        },
      ];
      await s.sync();
      expect(() => s.check(_claims('usr_bob', 'ses_1', t0)),
          _code(VerifierErrorCode.revoked));
      expect(() => s.check(_claims('usr_carol', 'ses_9', t0)),
          _code(VerifierErrorCode.revoked));
      // A token issued after the subject revocation is unaffected.
      s.check(
          _claims('usr_carol', 'ses_9', now.add(const Duration(seconds: 1))));
      s.check(_claims('usr_alice', 'ses_2', t0));
      // user.recovery_restricted is not a revocation.
      s.check(_claims('usr_dave', 'ses_3', t0));
      clock.advance(const Duration(seconds: 120));
      expect(() => s.check(_claims('usr_alice', 'ses_2', t0)),
          _code(VerifierErrorCode.staleState));
      expect(challenge(VerifierException(VerifierErrorCode.staleState)).status,
          503);
    });

    test('fails closed before start()', () {
      expect(() => state().check(_claims('usr_1', 'ses_1', clock.now)),
          _code(VerifierErrorCode.staleState));
    });

    test('wraps an authenticator', () async {
      final s = state();
      await s.start();
      final v = BoundedVerifier(
          _Stub(_claims('usr_x', 'ses_x',
              clock.now.subtract(const Duration(milliseconds: 10)))),
          s);
      expect((await v.authenticate('raw')).subject, 'usr_x');
      pending = [_revoked('ses_x', clock.now)];
      await s.sync();
      await expectLater(
          v.authenticate('raw'), _code(VerifierErrorCode.revoked));
    });

    test(
        'reads subject_id for role unassignment and refresh reuse, for user subjects only',
        () async {
      final s = state();
      await s.start();
      final at = _iso(clock.now);
      final t0 = clock.now.subtract(const Duration(seconds: 1));
      pending = [
        {
          'event_type': 'authorization.role.unassigned',
          'occurred_at': at,
          'organization_id': 'org_1',
          'data': {'subject_id': 'usr_dan', 'role_id': 'rol_1'},
        },
        {
          'event_type': 'authorization.role.unassigned',
          'occurred_at': at,
          'organization_id': 'org_1',
          'data': {'subject_id': 'svc_batch', 'role_id': 'rol_1'},
        },
        {
          'event_type': 'security.refresh_reuse_detected',
          'occurred_at': at,
          'data': {'subject_id': 'usr_erin', 'family_id': 'rff_1'},
        },
        {
          'event_type': 'security.refresh_reuse_detected',
          'occurred_at': at,
          'data': {'subject_id': 'svc_batch', 'family_id': 'rff_2'},
        },
        {
          'event_type': 'organization.suspended',
          'occurred_at': at,
          'organization_id': 'org_9',
          'data': <String, Object?>{},
        },
      ];
      await s.sync();
      expect(() => s.check(_claims('usr_dan', 'ses_d', t0, 'org_1')),
          _code(VerifierErrorCode.revoked));
      s.check(_claims('usr_dan', 'ses_d', t0, 'org_2'));
      expect(() => s.check(_claims('usr_erin', 'ses_e', t0, '')),
          _code(VerifierErrorCode.revoked));
      expect(() => s.check(_claims('usr_zed', 'ses_z', t0, 'org_9')),
          _code(VerifierErrorCode.revoked));
      // A service principal subject is not mistaken for a user.
      s.check(_claims('svc_batch', 'ses_s', t0));
    });

    test('reports stream failures as unavailable without accepting bad pages',
        () async {
      final s = state();
      await s.start();
      for (final bad in [
        [
          {
            'event_type': 'session.revoked',
            'occurred_at': 'yesterday',
            'data': <String, Object?>{}
          },
        ],
        [
          {
            'event_type': 'session.revoked',
            'occurred_at': '2026-10-10 10:00:00'
          },
        ],
        ['garbage'],
      ]) {
        pending = bad;
        await expectLater(s.sync(), _code(VerifierErrorCode.unavailable));
      }
      final failing = BoundedState(
        baseUrl: idp.url,
        realm: 'main',
        token: () => throw StateError('vault down'),
        maxStaleness: const Duration(seconds: 60),
        httpClient: client,
      );
      await expectLater(failing.start(), _code(VerifierErrorCode.unavailable));
    });

    test('validates configuration', () {
      expect(
          () => BoundedState(
              baseUrl: idp.url,
              realm: 'main',
              token: () => 't',
              maxStaleness: Duration.zero),
          throwsArgumentError);
      expect(
          () => BoundedState(
              baseUrl: 'ftp://x',
              realm: 'main',
              token: () => 't',
              maxStaleness: const Duration(seconds: 1)),
          throwsArgumentError);
    });
  });

  group('bounded-state restarts and expired cursors', () {
    final t0 = DateTime.utc(2026, 10, 10, 10);

    test('keeps known revocations when start() is called again', () async {
      final f = _fakeStream((cursor) {
        if (cursor == 'now') {
          return (200, {'events': <Object?>[], 'next_cursor': '1.0'});
        }
        if (cursor == '1.0') {
          return (
            200,
            {
              'next_cursor': '2.0',
              'events': [
                _revoked('ses_1', t0),
                {
                  'event_type': 'user.suspended',
                  'occurred_at': _iso(t0),
                  'data': {'user_id': 'usr_2'},
                },
              ],
            }
          );
        }
        return (200, {'events': <Object?>[], 'next_cursor': cursor});
      });
      final s = BoundedState(
          baseUrl: 'https://id.test',
          realm: 'main',
          token: () => 't',
          maxStaleness: const Duration(seconds: 60),
          httpClient: f.client,
          now: () => t0);
      await s.start();
      await s.sync();
      await s.start();
      final before = t0.subtract(const Duration(seconds: 1));
      expect(() => s.check(_claims('usr_9', 'ses_1', before)),
          _code(VerifierErrorCode.revoked));
      expect(() => s.check(_claims('usr_2', 'ses_9', before)),
          _code(VerifierErrorCode.revoked));
    });

    test(
        'rewinds to the retained history on 410 and is fresh only once caught up',
        () async {
      var now = t0;
      var midReplayFails = true;
      final full = List.generate(500,
          (i) => _revoked('ses_old_$i', t0.subtract(const Duration(hours: 1))));
      final f = _fakeStream((cursor) => switch (cursor) {
            'now' => (200, {'events': <Object?>[], 'next_cursor': '5.0'}),
            '5.0' => (
                200,
                {
                  'events': [_revoked('ses_known', t0)],
                  'next_cursor': '6.0'
                }
              ),
            '6.0' => (410, {'code': 'cursor_expired'}),
            '' => (200, {'events': full, 'next_cursor': 'p1'}),
            'p1' => midReplayFails
                ? (503, <String, Object?>{})
                : (
                    200,
                    {
                      'events': [_revoked('ses_gap', t0)],
                      'next_cursor': '9.0'
                    }
                  ),
            _ => (200, {'events': <Object?>[], 'next_cursor': cursor}),
          });
      final s = BoundedState(
          baseUrl: 'https://id.test',
          realm: 'main',
          token: () => 't',
          maxStaleness: const Duration(seconds: 60),
          httpClient: f.client,
          now: () => now);
      await s.start();
      await s.sync();
      await expectLater(
          s.sync(),
          throwsA(isA<CursorExpiredException>()
              .having((e) => e.code, 'code', VerifierErrorCode.unavailable)));
      expect(() => s.check(_claims('usr_1', 'ses_known', t0)),
          _code(VerifierErrorCode.revoked));
      // The replay applies a full page, then fails: not fresh, it has not
      // caught up.
      now = now.add(const Duration(seconds: 30));
      await expectLater(s.sync(), _code(VerifierErrorCode.unavailable));
      now = now.add(const Duration(seconds: 40));
      expect(() => s.check(_claims('usr_1', 'ses_other', t0)),
          _code(VerifierErrorCode.staleState));
      midReplayFails = false;
      await s.sync();
      for (final sid in ['ses_known', 'ses_gap', 'ses_old_0']) {
        expect(() => s.check(_claims('usr_1', sid, t0)),
            _code(VerifierErrorCode.revoked),
            reason: sid);
      }
      s.check(_claims('usr_1', 'ses_other', t0));
      expect(f.cursors.sublist(0, 4), ['now', '5.0', '6.0', '']);
    });

    test(
        'run() reports the 410, replays the retained history and keeps following',
        () async {
      var expired = 0;
      final f = _fakeStream((cursor) {
        switch (cursor) {
          case 'now':
            return (200, {'events': <Object?>[], 'next_cursor': '1.0'});
          case '1.0':
            expired++;
            return (410, {'code': 'cursor_expired'});
          case '':
            return (
              200,
              {
                'events': [_revoked('ses_gap', t0)],
                'next_cursor': '2.0'
              }
            );
          case '2.0':
            return (
              200,
              {
                'events': [_revoked('ses_next', t0)],
                'next_cursor': '3.0'
              }
            );
          default:
            return (200, {'events': <Object?>[], 'next_cursor': cursor});
        }
      });
      final s = BoundedState(
          baseUrl: 'https://id.test',
          realm: 'main',
          token: () => 't',
          maxStaleness: const Duration(seconds: 60),
          httpClient: f.client,
          now: () => t0);
      await s.start();
      final stop = CancelToken();
      final errors = <Object>[];
      final running = s.run(stop, onError: errors.add);
      final deadline = DateTime.now().add(const Duration(seconds: 5));
      for (;;) {
        try {
          s.check(_claims('usr_1', 'ses_next', t0));
        } on VerifierException catch (e) {
          if (e.code == VerifierErrorCode.revoked) break;
          rethrow;
        }
        if (DateTime.now().isAfter(deadline)) {
          fail('run() did not recover from the expired cursor');
        }
        await sleep(5);
      }
      stop.cancel();
      await running;
      expect(() => s.check(_claims('usr_1', 'ses_gap', t0)),
          _code(VerifierErrorCode.revoked));
      expect(expired, 1);
      expect(errors, hasLength(1));
      expect(errors.single, isA<CursorExpiredException>());
    });

    test('never weakens a revocation when an older event is replayed',
        () async {
      final t2 = t0;
      final t1 = t0.subtract(const Duration(hours: 1));
      Map<String, Object?> suspended(DateTime at) => {
            'event_type': 'user.suspended',
            'occurred_at': _iso(at),
            'data': {'user_id': 'usr_1'},
          };
      final f = _fakeStream((cursor) {
        if (cursor == 'now') {
          return (200, {'events': <Object?>[], 'next_cursor': '1.0'});
        }
        if (cursor == '1.0') {
          return (
            200,
            {
              'events': [suspended(t2), suspended(t1)],
              'next_cursor': '2.0'
            }
          );
        }
        return (200, {'events': <Object?>[], 'next_cursor': cursor});
      });
      final s = BoundedState(
          baseUrl: 'https://id.test',
          realm: 'main',
          token: () => 't',
          maxStaleness: const Duration(seconds: 60),
          httpClient: f.client,
          now: () => t0);
      await s.start();
      await s.sync();
      expect(
          () => s.check(_claims(
              'usr_1', 'ses_1', t2.subtract(const Duration(minutes: 1)))),
          _code(VerifierErrorCode.revoked));
      s.check(_claims('usr_1', 'ses_1', t2.add(const Duration(seconds: 1))));
    });

    test('long polls with wait (clamped to 25 s) and limit=500', () async {
      final queries = <Map<String, String>>[];
      final client = MockClient((req) async {
        queries.add(req.url.queryParameters);
        return http.Response(
            jsonEncode({'events': <Object?>[], 'next_cursor': 'c'}), 200);
      });
      final s = BoundedState(
          baseUrl: 'https://id.test/',
          realm: 'main realm',
          token: () => 't',
          maxStaleness: const Duration(seconds: 60),
          httpClient: client);
      await s.start();
      await s.sync(wait: const Duration(seconds: 90));
      expect(queries.last, {'cursor': 'c', 'limit': '500', 'wait': '25'});
    });
  });

  group('bounded-state run stops promptly', () {
    test('cancelling stops an in-flight long poll and a backoff at once',
        () async {
      var calls = 0;
      final hanging = MockClient((req) {
        calls++;
        if (calls == 1) {
          throw StateError('first poll fails'); // forces a backoff
        }
        return Completer<http.Response>().future; // never answers
      });
      final s = BoundedState(
          baseUrl: 'http://idp.test',
          realm: 'main',
          maxStaleness: const Duration(seconds: 60),
          token: () => 't',
          httpClient: hanging);
      final stop = CancelToken();
      final watch = Stopwatch()..start();
      final running = s.run(stop, onError: (_) {});
      await sleep(50);
      stop.cancel();
      await running;
      expect(watch.elapsedMilliseconds, lessThan(1000));

      // And during a long poll.
      final stop2 = CancelToken();
      calls = 1; // the next poll hangs
      final running2 = s.run(stop2, onError: (_) {});
      await sleep(50);
      watch.reset();
      stop2.cancel();
      await running2;
      expect(watch.elapsedMilliseconds, lessThan(500));
    });
  });
}

class _Stub implements Authenticator {
  _Stub(this.claims);
  final Claims claims;
  @override
  Future<Claims> authenticate(String raw, {CancelToken? cancelToken}) async =>
      claims;
}
