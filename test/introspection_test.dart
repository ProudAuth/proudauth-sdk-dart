import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:proudauth_sdk/introspection.dart';
import 'package:proudauth_sdk/io.dart';
import 'package:test/test.dart';

import 'support/server.dart';

const _iss = 'https://id.test/realms/main';
const _aud = 'https://api.test/orders';
const _clientId = 'orders-api:rs';
const _clientSecret = 'pa_cs_s3cr3t+/= &x';

typedef _Entry = Object? Function(int count);

Matcher _code(VerifierErrorCode code) =>
    throwsA(isA<VerifierException>().having((e) => e.code, 'code', code));

Future<void> _rejects(Future<Object?> f, VerifierErrorCode code) =>
    expectLater(f, _code(code));

Map<String, Object?> _active([Map<String, Object?> extra = const {}]) => {
      'active': true,
      'iss': _iss,
      'sub': 'usr_1',
      'aud': _aud,
      'client_id': 'web',
      'scope': 'orders:read',
      'exp': 1800000300,
      'iat': 1800000000,
      'jti': 'tok_1',
      'sid': 'ses_1',
      'org_id': 'org_a',
      'token_kind': 'user_access',
      'token_type': 'Bearer',
      'authz_version': 7,
      ...extra,
    }..removeWhere((_, v) => v == null);

Map<String, Object?> _support([Map<String, Object?> extra = const {}]) =>
    _active({
      'sub': 'usr_customer',
      'client_id': 'support-bff',
      'jti': 'tok_support_1',
      'token_kind': 'impersonation_access',
      'act': {'iss': _iss, 'sub': 'usr_agent'},
      'impersonation_grant_id': 'imp_1',
      'support_mode': 'read_only',
      ...extra,
    });

void main() {
  late TestServer idp;
  late http.Client client;
  final tokens = <String, _Entry>{};
  var lastAuth = '';
  var lastBody = '';
  var lastType = '';
  var mode = 'ok';
  var introspections = 0;

  void setToken(String t, Object? v) => tokens[t] = (_) => v;

  setUpAll(() async {
    idp = await TestServer.start((req, body) async {
      if (req.method != 'POST' || req.uri.path != '/oauth/introspect') {
        return respondJson(req, 404, {});
      }
      introspections++;
      lastAuth = req.headers.value('authorization') ?? '';
      lastType = req.headers.value('content-type') ?? '';
      lastBody = body;
      switch (mode) {
        case 'error':
          return respondJson(req, 500, {'error': 'server_error'});
        case 'slow':
          await sleep(300);
        case 'garbage':
          return respondJson(req, 200, '<html>');
        case 'dup':
          return respondJson(
              req, 200, '{"active":false,"active":true,"iss":"$_iss"}');
        case 'array':
          return respondJson(req, 200, '[{"active":true}]');
        case 'huge':
          return respondJson(req, 200, {..._active(), 'pad': 'x' * (70 << 10)});
      }
      final tok = Uri.splitQueryString(body)['token'] ?? '';
      final entry = tokens[tok];
      return respondJson(
          req, 200, entry == null ? {'active': false} : entry(introspections));
    });
    client = http.Client();
  });
  tearDownAll(() async {
    client.close();
    await idp.close();
  });
  setUp(() {
    mode = 'ok';
    tokens.clear();
  });

  Introspector intro({
    String? endpoint,
    String issuer = _iss,
    String audience = _aud,
    String clientSecret = _clientSecret,
    List<String>? acceptedKinds,
  }) =>
      Introspector(
        endpoint: endpoint ?? '${idp.url}/oauth/introspect',
        clientId: _clientId,
        clientSecret: clientSecret,
        issuer: issuer,
        audience: audience,
        timeout: const Duration(milliseconds: 150),
        acceptedKinds: acceptedKinds,
        httpClient: client,
      );

  test('authenticates with client_secret_basic and form-encoded credentials',
      () async {
    setToken('pa_at_abc', _active());
    final c = await intro().authenticate('pa_at_abc');
    expect(c.subject, 'usr_1');
    expect(c.online, isTrue);
    expect(c.authzVersion, 7);
    expect(c.expiry,
        DateTime.fromMillisecondsSinceEpoch(1800000300000, isUtc: true));
    expect(lastType, 'application/x-www-form-urlencoded');
    expect(lastBody, 'token=pa_at_abc');
    final decoded = utf8
        .decode(base64.decode(lastAuth.replaceFirst(RegExp('^Basic '), '')));
    expect(decoded, 'orders-api%3Ars:pa_cs_s3cr3t%2B%2F%3D+%26x');
    final parts = decoded.split(':').map(Uri.decodeQueryComponent).toList();
    expect(parts, [_clientId, _clientSecret]);
  });

  test('accepts JWT access tokens too (form-encodes the token)', () async {
    setToken('a.b+c.d', _active());
    await intro().authenticate('a.b+c.d');
    expect(lastBody, 'token=a.b%2Bc.d');
  });

  test('refuses sender-bound opaque tokens through token-only introspection',
      () async {
    for (final cnf in <Object?>[
      {'jkt': 'x' * 43},
      {'x5t#S256': 'x' * 43},
      null,
      <String, Object?>{},
      {'unknown': 'binding'},
    ]) {
      final result = _active()..['cnf'] = cnf;
      setToken('bound', result);
      await _rejects(
          intro().authenticate('bound'), VerifierErrorCode.senderConstraint);
    }
  });

  test('denies inactive tokens', () async {
    setToken('t', {'active': false});
    await _rejects(intro().authenticate('t'), VerifierErrorCode.inactive);
    setToken('t2', {
      'active': 'true',
      'iss': _iss,
      'aud': _aud,
      'token_kind': 'user_access'
    });
    await _rejects(intro().authenticate('t2'), VerifierErrorCode.inactive);
  });

  test('never caches: a revocation is visible on the next request', () async {
    var revoked = false;
    tokens['t'] = (_) => revoked ? {'active': false} : _active();
    final i = intro();
    final before = introspections;
    await i.authenticate('t');
    await i.authenticate('t');
    revoked = true;
    await _rejects(i.authenticate('t'), VerifierErrorCode.inactive);
    expect(introspections - before, 3);
  });

  test(
      'fails closed on HTTP errors, bad JSON, timeouts and network errors (TEST-035)',
      () async {
    setToken('t', _active());
    for (final m in ['error', 'garbage', 'dup', 'array', 'slow', 'huge']) {
      mode = m;
      await expectLater(
          intro().authenticate('t'), _code(VerifierErrorCode.unavailable),
          reason: m);
    }
    mode = 'ok';
    await _rejects(
        intro(endpoint: '${await deadUrl()}/oauth/introspect')
            .authenticate('t'),
        VerifierErrorCode.unavailable);
    final cancelled = CancelToken()..cancel();
    await _rejects(intro().authenticate('t', cancelToken: cancelled),
        VerifierErrorCode.unavailable);
  });

  test('does not follow redirects with client credentials', () async {
    final redirector = await TestServer.start((req, _) async {
      req.response
        ..statusCode = 307
        ..headers.set('location', '${idp.url}/oauth/introspect');
      await req.response.close();
    });
    try {
      setToken('t', _active());
      final before = introspections;
      await _rejects(
          intro(endpoint: '${redirector.url}/introspect').authenticate('t'),
          VerifierErrorCode.unavailable);
      expect(introspections, before);
    } finally {
      await redirector.close();
    }
  });

  test('checks issuer and audience of the introspection result', () async {
    setToken('t1', _active({'iss': 'https://other.test'}));
    await _rejects(intro().authenticate('t1'), VerifierErrorCode.issuer);
    setToken('t2', _active({'aud': 'https://api.test/billing'}));
    await _rejects(intro().authenticate('t2'), VerifierErrorCode.audience);
    setToken(
        't3',
        _active({
          'aud': [_aud, 'https://api.test/billing']
        }));
    await _rejects(intro().authenticate('t3'), VerifierErrorCode.audience);
    setToken(
        't4',
        _active({
          'aud': [_aud]
        }));
    await intro().authenticate('t4');
  });

  test('rejects support tokens on ordinary paths (IMP-001, TEST-045)',
      () async {
    setToken(
        'pa_it_1',
        _active({
          'token_kind': 'impersonation_access',
          'act': {'sub': 'usr_agent'},
          'impersonation_grant_id': 'imp_1',
        }));
    await _rejects(
        intro().authenticate('pa_it_1'), VerifierErrorCode.tokenKind);
    setToken('x', _active({'token_kind': 'refresh'}));
    await _rejects(intro().authenticate('x'), VerifierErrorCode.tokenKind);
  });

  test('rejects missing and oversized tokens without a network call', () async {
    final before = introspections;
    await _rejects(intro().authenticate(''), VerifierErrorCode.missingToken);
    await _rejects(
        intro().authenticate('x' * 9000), VerifierErrorCode.tooLarge);
    expect(introspections, before);
  });

  test('validates configuration', () {
    Matcher argError(String text) => throwsA(isA<ArgumentError>()
        .having((e) => '${e.message}', 'message', contains(text)));
    expect(() => intro(audience: ''), argError('audience is required'));
    expect(() => intro(issuer: ''), argError('issuer is required'));
    expect(() => intro(clientSecret: ''), argError('clientSecret is required'));
    expect(() => intro(endpoint: 'ftp://x'), argError('http'));
    expect(() => intro(acceptedKinds: ['user_access', 'impersonation_access']),
        argError('SupportGuard'));
  });

  group('SupportGuard', () {
    ({SupportGuard guard, List<SupportEvent> events, List<String> order})
        setup({
      SupportAuditor? auditor,
      List<String> writeOperations = const ['orders.annotate'],
    }) {
      final events = <SupportEvent>[];
      final order = <String>[];
      final guard = SupportGuard(
        introspector: intro(),
        auditor: auditor ??
            SupportAuditor.from((ev, _) async {
              order.add('audit');
              await sleep(5);
              events.add(ev);
            }),
        writeOperations: writeOperations,
      );
      return (guard: guard, events: events, order: order);
    }

    test('requires an operation for route authenticators', () {
      expect(
          () => setup().guard.operation('', read: true), throwsArgumentError);
    });

    test('allows a read with actor attribution, auditing before access',
        () async {
      setToken('pa_it_1', _support());
      final s = setup();
      final c = await s.guard.authorize('pa_it_1', 'orders.list', read: true);
      s.order.add('access');
      expect(s.order, ['audit', 'access']);
      expect(c.isSupport, isTrue);
      expect(c.actor?.subject, 'usr_agent');
      expect(c.subject, 'usr_customer');
      expect(s.events, hasLength(1));
      final ev = s.events.single;
      expect(ev.allowed, isTrue);
      expect(ev.denyReason, isNull);
      expect(ev.actor, 'usr_agent');
      expect(ev.actorIssuer, _iss);
      expect(ev.subject, 'usr_customer');
      expect(ev.grantId, 'imp_1');
      expect(ev.orgId, 'org_a');
      expect(ev.clientId, 'support-bff');
      expect(ev.operation, 'orders.list');
      expect(ev.tokenId, 'tok_support_1');
      expect(ev.read, isTrue);
    });

    test('denies writes in read_only mode and audits the denial (IMP-011)',
        () async {
      setToken('pa_it_1', _support());
      final s = setup();
      await _rejects(
          s.guard.authorize('pa_it_1', 'orders.annotate', read: false),
          VerifierErrorCode.supportPolicy);
      expect(s.events, hasLength(1));
      expect(s.events.single.allowed, isFalse);
      expect(s.events.single.denyReason, SupportDenyReason.writeNotAllowlisted);
    });

    test('treats an operation declared as a write as a write', () async {
      setToken('pa_it_1', _support());
      await _rejects(
          setup().guard.authorize('pa_it_1', 'orders.list', read: false),
          VerifierErrorCode.supportPolicy);
    });

    test('allows only allowlisted writes in allowlisted_write mode', () async {
      setToken('pa_it_w', _support({'support_mode': 'allowlisted_write'}));
      final s = setup();
      await s.guard.authorize('pa_it_w', 'orders.annotate', read: false);
      await s.guard.authorize('pa_it_w', 'Orders.Annotate', read: false);
      await _rejects(s.guard.authorize('pa_it_w', 'orders.cancel', read: false),
          VerifierErrorCode.supportPolicy);
    });

    test(
        'always denies protected operations, even allowlisted (IMP-012, IMP-013, TEST-042)',
        () async {
      setToken('pa_it_w', _support({'support_mode': 'allowlisted_write'}));
      const ops = [
        'password.change', 'password.reset', 'mfa.change.totp', //
        'api_key.create', 'payment', 'refund', 'orders.delete',
        'users.password.change', 'DELETE',
      ];
      final s = setup(writeOperations: ops);
      for (final op in ops) {
        await _rejects(s.guard.authorize('pa_it_w', op, read: false),
            VerifierErrorCode.supportPolicy);
        await _rejects(s.guard.authorize('pa_it_w', op, read: true),
            VerifierErrorCode.supportPolicy);
      }
      expect(s.events, hasLength(ops.length * 2));
      expect(
          s.events.every((e) =>
              !e.allowed &&
              e.denyReason == SupportDenyReason.protectedOperation),
          isTrue);
      // A protected segment anywhere in the name counts (same rule as Go).
      expect(isProtectedOperation('orders.refund.read'), isTrue);
      expect(isProtectedOperation('orders.list'), isFalse);
      expect(isProtectedOperation('refund.read'), isTrue);
      expect(isProtectedOperation('orders.export', ['orders.export']), isTrue);
      // Additional protected operations add to the defaults.
      setToken('pa_it_1', _support());
      final extra = SupportGuard(
        introspector: intro(),
        auditor: SupportAuditor.from((_, __) {}),
        protectedOperations: ['orders.export'],
      );
      await _rejects(extra.authorize('pa_it_1', 'orders.export', read: true),
          VerifierErrorCode.supportPolicy);
      await _rejects(extra.authorize('pa_it_1', 'secrets.list', read: true),
          VerifierErrorCode.supportPolicy);
    });

    test('denies when the audit record cannot be written (IMP-020, TEST-047)',
        () async {
      setToken('pa_it_1', _support());
      final sync = setup(
          auditor: SupportAuditor.from((_, __) => throw StateError('db down')));
      await _rejects(sync.guard.authorize('pa_it_1', 'orders.list', read: true),
          VerifierErrorCode.unavailable);
      final async = setup(
          auditor: SupportAuditor.from(
              (_, __) => Future<void>.error(StateError('db down'))));
      await _rejects(
          async.guard.authorize('pa_it_1', 'orders.list', read: true),
          VerifierErrorCode.unavailable);
    });

    test('requires a preserved actor and grant (TEST-045)', () async {
      final s = setup();
      setToken('a', _support({'act': null}));
      await _rejects(s.guard.authorize('a', 'orders.list', read: true),
          VerifierErrorCode.tokenKind);
      setToken(
          'b',
          _support({
            'act': {'sub': ''}
          }));
      await _rejects(s.guard.authorize('b', 'orders.list', read: true),
          VerifierErrorCode.tokenKind);
      setToken('c', _support({'impersonation_grant_id': null}));
      await _rejects(s.guard.authorize('c', 'orders.list', read: true),
          VerifierErrorCode.tokenKind);
      setToken(
          'd',
          _active({
            'act': {'sub': 'usr_agent'}
          }));
      await _rejects(s.guard.authorize('d', 'orders.list', read: true),
          VerifierErrorCode.tokenKind);
      expect(s.events, isEmpty);
    });

    test(
        'denies after revocation and when introspection is unavailable, without auditing access (TEST-043/044)',
        () async {
      var revoked = false;
      tokens['pa_it_1'] = (_) => revoked ? {'active': false} : _support();
      final s = setup();
      await s.guard.authorize('pa_it_1', 'orders.list', read: true);
      revoked = true;
      await _rejects(s.guard.authorize('pa_it_1', 'orders.list', read: true),
          VerifierErrorCode.inactive);
      mode = 'error';
      await _rejects(s.guard.authorize('pa_it_1', 'orders.list', read: true),
          VerifierErrorCode.unavailable);
      expect(s.events, hasLength(1));
    });

    test(
        'authorizeAny routes by the authoritative token_kind with one introspection',
        () async {
      setToken('pa_at_user', _active());
      setToken('pa_at_disguised', _support()); // the prefix does not matter
      final s = setup();
      final before = introspections;
      final u = await s.guard
          .authorizeAny('pa_at_user', 'orders.annotate', read: false);
      expect(u.isSupport, isFalse);
      await _rejects(
          s.guard
              .authorizeAny('pa_at_disguised', 'orders.annotate', read: false),
          VerifierErrorCode.supportPolicy);
      final sup = await s.guard
          .authorizeAny('pa_at_disguised', 'orders.list', read: true);
      expect(sup.isSupport, isTrue);
      expect(introspections - before, 3);
      expect(s.events, hasLength(2));
      setToken('pa_x', _active({'token_kind': 'refresh'}));
      await _rejects(s.guard.authorizeAny('pa_x', 'orders.list', read: true),
          VerifierErrorCode.tokenKind);
    });

    test('dart:io adapter answers with distinct statuses', () async {
      setToken('pa_it_1', _support());
      setToken('pa_at_user', _active());
      final s = setup();
      final readHandler = protectOperation(
          s.guard, (req, claims) => req.response.close(),
          operation: 'orders.list', read: true);
      final writeHandler = protectOperation(
          s.guard, (req, claims) => req.response.close(),
          operation: 'orders.annotate', read: false);
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((req) =>
          req.uri.path == '/write' ? writeHandler(req) : readHandler(req));
      final base = 'http://127.0.0.1:${server.port}';
      Future<int> call(String path, [String? tok]) async =>
          (await client.get(Uri.parse('$base$path'),
                  headers: tok == null ? {} : {'authorization': 'Bearer $tok'}))
              .statusCode;
      try {
        expect(await call('/read', 'pa_it_1'), 200);
        expect(await call('/write', 'pa_it_1'), 403);
        expect(await call('/write', 'pa_at_user'), 200);
        expect(await call('/read', 'pa_at_unknown'), 401);
        expect(await call('/read'), 401);
        mode = 'error';
        expect(await call('/read', 'pa_it_1'), 503);
      } finally {
        await server.close(force: true);
      }
    });
  });
}
