/// Bounded-state verification (SDK-002), a port of the Node.js SDK's
/// `bounded-state.ts`: the consistency mode between offline JWT
/// verification and per-request introspection. Tokens are verified locally,
/// then checked against revocation state replayed from the identity
/// provider's session-event stream (SES-019). The state is trusted only
/// while it is fresher than `maxStaleness`; beyond that every check fails
/// with `stale_state` (HTTP 503). It never silently downgrades to offline
/// acceptance.
library;

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'cancel.dart';
import 'claims.dart';
import 'errors.dart';
import 'internal/http.dart';
import 'middleware.dart';

/// Thrown by [BoundedState.sync] when the stream answers 410: the cursor is
/// older than the retained history. `sync` has already rewound to the
/// beginning of the retained history (keeping every revocation it knows),
/// so the next `sync` replays it; [BoundedState.run] does so immediately.
/// Its code is `unavailable`.
final class CursorExpiredException extends VerifierException {
  CursorExpiredException()
      : super(
          VerifierErrorCode.unavailable,
          cause: StateError(
              'session-event cursor is older than the retained history (HTTP 410)'),
        );
}

const Set<String> _subjectEvents = {
  // user.recovery_restricted is not a revocation: the server keeps sessions
  // valid.
  'user.suspended', 'user.locked', 'user.deleted', 'user.password_reset', //
  'security.refresh_reuse_detected', 'security.credential_compromised',
};
const Set<String> _orgEvents = {
  'organization.suspended',
  'organization.deleted',
  'organization.archived',
};
const Set<String> _memberEvents = {
  'organization.membership.removed',
  'organization.membership.suspended',
  'authorization.role.unassigned',
};

/// Events naming the assignment's or grant's subject as `subject_id` rather
/// than `user_id`. The subject may also be a service principal (`svc_`) or
/// a group (`grp_`); the ID prefix tells them apart, and only users are
/// tracked.
const Set<String> _subjectIdEvents = {
  'authorization.role.unassigned',
  'security.refresh_reuse_detected',
};

/// Page size requested from the stream (its maximum).
const int _pageLimit = 500;

/// Pages one `sync()` call reads at most.
const int _maxPagesPerSync = 100;

/// Session-event pages larger than this are refused (8 MiB, as in Go).
const int _maxPageBytes = 8 << 20;

/// Longest long-poll the stream accepts.
const int _maxWaitSeconds = 25;

final class _Event {
  _Event(this.type, this.at, this.orgId, this.data);
  final String type;
  final int at; // microseconds since the epoch
  final String orgId;
  final Map<String, Object?> data;

  String str(String k) {
    final v = data[k];
    return v is String ? v : '';
  }
}

final class _Page {
  _Page(this.events, this.nextCursor);
  final List<_Event> events;
  final String nextCursor;
}

/// Follows the session-event stream and answers revocation questions for
/// verified claims.
final class BoundedState {
  /// - [baseUrl]: identity provider origin, e.g. `https://id.example.com`.
  /// - [token]: returns a service access token (admin audience) carrying
  ///   `realm.session_events.read`.
  /// - [maxStaleness]: how old the replayed state may be before every check
  ///   fails closed.
  /// - [timeout]: per-request deadline (default 30 s; long polls wait at
  ///   most 25 s).
  factory BoundedState({
    required String baseUrl,
    required String realm,
    required FutureOr<String> Function() token,
    required Duration maxStaleness,
    Duration timeout = const Duration(seconds: 30),
    http.Client? httpClient,
    DateTime Function()? now,
  }) {
    if (maxStaleness <= Duration.zero) {
      throw ArgumentError('bounded-state: maxStaleness must be positive');
    }
    if (realm.isEmpty) throw ArgumentError('bounded-state: realm is required');
    if (timeout <= Duration.zero) {
      throw ArgumentError('bounded-state: timeout must be positive');
    }
    requireHttpUrl(baseUrl, 'baseUrl', 'bounded-state');
    return BoundedState._(
      '${trimTrailingSlashes(baseUrl)}/api/v1/realms/${Uri.encodeComponent(realm)}/session-events',
      token,
      maxStaleness,
      timeout,
      httpClient ?? http.Client(),
      httpClient == null,
      now ?? DateTime.now,
    );
  }

  BoundedState._(this._url, this._token, this._maxStaleness, this._timeout,
      this._client, this._ownsClient, this._now);

  final String _url;
  final FutureOr<String> Function() _token;
  final Duration _maxStaleness;
  final Duration _timeout;
  final http.Client _client;
  final bool _ownsClient;
  final DateTime Function() _now;

  String _cursor = '';
  DateTime? _synced;
  final Map<String, int> _sessions = {};
  final Map<String, int> _subjects = {};
  final Map<String, int> _orgs = {};
  final Map<String, int> _members = {};

  /// Closes the HTTP client the state created (not one passed in).
  void close() {
    if (_ownsClient) _client.close();
  }

  Future<_Page> _get(
      Map<String, String> query, CancelToken? cancelToken) async {
    final HttpResult res;
    try {
      final tok = await _token();
      res = await sendRequest(
        _client,
        method: 'GET',
        url: Uri.parse('$_url?${Uri(queryParameters: query).query}'),
        headers: {'authorization': 'Bearer $tok', 'accept': 'application/json'},
        timeout: _timeout,
        cancelToken: cancelToken,
        maxBodyBytes: _maxPageBytes,
        readBody: (status) => status == 200,
      );
    } catch (cause) {
      throw VerifierException(VerifierErrorCode.unavailable, cause: cause);
    }
    if (res.status == 410) throw CursorExpiredException();
    if (res.status != 200) {
      throw VerifierException(VerifierErrorCode.unavailable,
          cause: StateError('session-event stream returned ${res.status}'));
    }
    try {
      return _parsePage(jsonDecode(utf8.decode(res.body)));
    } catch (cause) {
      throw VerifierException(VerifierErrorCode.unavailable, cause: cause);
    }
  }

  static _Page _parsePage(Object? v) {
    if (v is! Map<String, Object?>) {
      throw const FormatException('page is not an object');
    }
    final cursor = v['next_cursor'];
    if (cursor is! String) throw const FormatException('next_cursor missing');
    final raw = v['events'];
    final events = <_Event>[];
    if (raw != null) {
      if (raw is! List<Object?>) throw const FormatException('events');
      for (final e in raw) {
        if (e is! Map<String, Object?>) throw const FormatException('event');
        final type = e['event_type'];
        final occurred = e['occurred_at'];
        if (type is! String || occurred is! String) {
          throw const FormatException('event_type or occurred_at');
        }
        final at = DateTime.tryParse(occurred);
        // RFC 3339 requires an offset; a local time is not a timestamp.
        if (at == null || !at.isUtc) {
          throw const FormatException('occurred_at');
        }
        final org = e['organization_id'];
        final data = e['data'];
        events.add(_Event(
          type,
          at.microsecondsSinceEpoch,
          org is String ? org : '',
          data is Map<String, Object?> ? data : const {},
        ));
      }
    }
    return _Page(events, cursor);
  }

  /// Positions the stream at "now"; call before accepting traffic. Calling
  /// it again keeps every revocation already replayed: the stream has no
  /// snapshot that could supersede them, so a restart only moves the
  /// position forward.
  Future<void> start({CancelToken? cancelToken}) async {
    final page = await _get(const {'from': 'now'}, cancelToken);
    _cursor = page.nextCursor;
    _synced = _now();
  }

  /// Reads all pending events ([wait] long-polls, at most 25 s). The state
  /// counts as fresh only once a read reaches the end of the stream, so a
  /// partly replayed backlog never passes for current state. A 410 rewinds
  /// to the beginning of the retained history (keeping the known
  /// revocations) and throws [CursorExpiredException]; the next `sync`
  /// replays that history, which includes the events after the expired
  /// cursor. Every failure is a [VerifierException] (`unavailable`).
  Future<void> sync({
    Duration wait = Duration.zero,
    CancelToken? cancelToken,
  }) async {
    for (var i = 0; i < _maxPagesPerSync; i++) {
      final cursor = _cursor;
      final query = {'cursor': cursor, 'limit': '$_pageLimit'};
      if (i == 0 && wait.inSeconds > 0) {
        query['wait'] = '${wait.inSeconds.clamp(0, _maxWaitSeconds)}';
      }
      final _Page page;
      try {
        page = await _get(query, cancelToken);
      } on CursorExpiredException {
        // No snapshot exists, so the full resynchronization is a replay of
        // the retained history ('' is its beginning). _synced is left alone:
        // the state turns stale if the replay does not catch up in time.
        if (_cursor == cursor) _cursor = '';
        rethrow;
      }
      for (final ev in page.events) {
        _apply(ev);
      }
      _cursor = page.nextCursor;
      if (page.events.length < _pageLimit) {
        _synced = _now();
        return;
      }
    }
  }

  void _apply(_Event ev) {
    var user = ev.str('user_id');
    if (_subjectIdEvents.contains(ev.type)) {
      final s = ev.str('subject_id');
      user = s.startsWith('usr_') ? s : '';
    }
    if (ev.type == 'session.revoked') {
      final sid = ev.str('session_id');
      if (sid.isNotEmpty) _revokeAt(_sessions, sid, ev.at);
    } else if (_subjectEvents.contains(ev.type)) {
      if (user.isNotEmpty) _revokeAt(_subjects, user, ev.at);
    } else if (_orgEvents.contains(ev.type)) {
      final org = ev.str('organization_id').isNotEmpty
          ? ev.str('organization_id')
          : ev.orgId;
      if (org.isNotEmpty) _revokeAt(_orgs, org, ev.at);
    } else if (_memberEvents.contains(ev.type)) {
      if (user.isNotEmpty && ev.orgId.isNotEmpty) {
        _revokeAt(_members, '$user|${ev.orgId}', ev.at);
      }
    }
  }

  /// Keeps the latest revocation time, so a replay never weakens the state.
  static void _revokeAt(Map<String, int> m, String key, int at) {
    final prev = m[key];
    if (prev == null || at > prev) m[key] = at;
  }

  /// Throws `stale_state` when the state is too old, `revoked` when the
  /// claims were revoked.
  void check(Claims c) {
    final synced = _synced;
    if (synced == null || _now().difference(synced) > _maxStaleness) {
      throw VerifierException(VerifierErrorCode.staleState);
    }
    final issued = c.issuedAt?.microsecondsSinceEpoch ?? 0;
    bool before(Map<String, int> m, String k) {
      final at = m[k];
      return at != null && issued <= at;
    }

    if (c.sessionId.isNotEmpty && _sessions.containsKey(c.sessionId)) {
      throw VerifierException(VerifierErrorCode.revoked);
    }
    if (before(_subjects, c.subject)) {
      throw VerifierException(VerifierErrorCode.revoked);
    }
    if (c.orgId.isNotEmpty &&
        (before(_orgs, c.orgId) ||
            before(_members, '${c.subject}|${c.orgId}'))) {
      throw VerifierException(VerifierErrorCode.revoked);
    }
  }

  /// Keeps the state current until [stop] is cancelled, long-polling the
  /// stream; errors go to [onError] (whose own failures are ignored). After
  /// a [CursorExpiredException] (reported too) it replays the retained
  /// history at once instead of waiting, then keeps following the stream.
  /// Cancelling [stop] ends an in-flight long poll and a backoff wait at
  /// once.
  Future<void> run(CancelToken stop,
      {void Function(Object error)? onError}) async {
    var backoff = const Duration(seconds: 1);
    var resyncing = false;
    while (!stop.isCancelled) {
      try {
        await sync(wait: const Duration(seconds: 20), cancelToken: stop);
        backoff = const Duration(seconds: 1);
        resyncing = false;
      } catch (err) {
        if (stop.isCancelled) return; // stopping, not failing
        reportError(onError, err);
        if (err is CursorExpiredException && !resyncing) {
          // sync() rewound to the retained history: replay it now. A second
          // 410 in a row waits like any other error.
          resyncing = true;
          continue;
        }
        await _sleep(backoff, stop);
        final doubled = backoff * 2;
        backoff = doubled > const Duration(seconds: 30)
            ? const Duration(seconds: 30)
            : doubled;
      }
    }
  }

  /// Waits [d], ending early (without keeping a timer alive) when [stop] is
  /// cancelled.
  static Future<void> _sleep(Duration d, CancelToken stop) {
    final done = Completer<void>();
    late final void Function() remove;
    final timer = Timer(d, () {
      remove();
      if (!done.isCompleted) done.complete();
    });
    remove = onCancel(stop, () {
      timer.cancel();
      if (!done.isCompleted) done.complete();
    });
    return done.future;
  }
}

/// Offline verification followed by a bounded-state check.
final class BoundedVerifier implements Authenticator {
  const BoundedVerifier(this.verifier, this.state);

  final Authenticator verifier;
  final BoundedState state;

  @override
  Future<Claims> authenticate(String raw, {CancelToken? cancelToken}) async {
    final claims = await verifier.authenticate(raw, cancelToken: cancelToken);
    state.check(claims);
    return claims;
  }
}
