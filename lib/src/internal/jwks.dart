/// A key cache for one trusted JWKS URL with bounded, coalesced refreshes
/// (§14.4, TEST-005), a port of the Node.js SDK's `internal/jwks.ts`. The URL
/// always comes from configuration (or the configured issuer's discovery
/// document), never from a token header such as jku or x5u.
///
/// Refresh semantics mirror the Go and Node.js SDKs:
///  - the first lookup loads the key set;
///  - an unknown kid triggers at most one refresh, and refreshes are spaced
///    by at least `minRefreshInterval`, so floods of random kids cannot cause
///    a request storm;
///  - concurrent callers share one in-flight fetch;
///  - a failed fetch keeps the previously known keys; a successful fetch
///    replaces the set (retired keys disappear).
library;

import 'dart:async';

import 'package:http/http.dart' as http;

import '../cancel.dart';
import 'http.dart';
import 'json.dart';
import 'jws.dart';

/// Why a key lookup failed.
enum JwksFailure { unavailable, unknownKey }

final class JwksException implements Exception {
  const JwksException(this.reason, {this.cause});
  final JwksFailure reason;
  final Object? cause;
  @override
  String toString() => reason == JwksFailure.unavailable
      ? 'key set unavailable'
      : 'unknown signing key';
}

/// Default limit for key-set documents (1 MiB, as in the Node.js SDK).
const int defaultJwksMaxBytes = 1 << 20;

final class JwksCache {
  JwksCache({
    required this.url,
    required this.client,
    required this.timeout,
    required this.minRefreshInterval,
    required this.now,
    this.maxBytes = defaultJwksMaxBytes,
  });

  final Uri url;
  final http.Client client;
  final Duration timeout;
  final Duration minRefreshInterval;
  final DateTime Function() now;
  final int maxBytes;

  Map<String, VerificationKey> _keys = const {};
  DateTime? _lastFetch;
  Future<void>? _inflight;
  int _fetchCount = 0;
  bool _everLoaded = false;
  bool _lastFailed = false;

  /// Number of key-set fetches started (diagnostics and tests).
  int get fetchCount => _fetchCount;

  Future<VerificationKey> getKey(String kid, CancelToken? cancelToken) async {
    await _refresh(false, cancelToken);
    var k = _keys[kid];
    if (k != null) return k;
    // One bounded refresh for an unknown kid.
    await _refresh(true, cancelToken);
    k = _keys[kid];
    if (k != null) return k;
    if (!_everLoaded && _lastFailed) {
      throw const JwksException(JwksFailure.unavailable);
    }
    throw const JwksException(JwksFailure.unknownKey);
  }

  static Object _unavailable() => const JwksException(JwksFailure.unavailable);

  Future<void> _refresh(bool force, CancelToken? cancelToken) async {
    final inflight = _inflight;
    if (inflight != null) {
      // Coalesce: wait for the in-flight fetch; its outcome is observed via
      // the key map.
      await waitFor<void>(
        inflight.then<void>((_) {}, onError: (Object _) {}),
        cancelToken,
        _unavailable,
      );
      return;
    }
    if (!force && _keys.isNotEmpty) return;
    final t = now();
    final last = _lastFetch;
    if (last != null && t.difference(last) < minRefreshInterval) return;
    _lastFetch = t;
    _fetchCount++;
    final p = _load();
    _inflight = p;
    // Registered before any waiter so the slot is free when they resume.
    p.then<void>((_) {}, onError: (Object _) {}).whenComplete(() {
      if (identical(_inflight, p)) _inflight = null;
    });
    await waitFor<void>(p, cancelToken, _unavailable);
  }

  Future<void> _load() async {
    try {
      // The shared fetch is bounded by its own timeout, not by one caller's
      // token.
      final res = await sendRequest(
        client,
        method: 'GET',
        url: url,
        headers: const {'accept': 'application/jwk-set+json, application/json'},
        timeout: timeout,
        maxBodyBytes: maxBytes,
        readBody: (status) => status == 200,
      );
      if (res.status != 200) {
        throw StateError('key set endpoint returned HTTP ${res.status}');
      }
      final set = parseStrictJsonBytes(res.body);
      if (set is! Map<String, Object?> || set['keys'] is! List<Object?>) {
        throw StateError('key set has no keys array');
      }
      final keys = <String, VerificationKey>{};
      final ambiguous = <String>{};
      for (final jwk in set['keys']! as List<Object?>) {
        final k = importJwk(jwk);
        if (k == null) continue;
        if (keys.containsKey(k.kid)) {
          ambiguous.add(k.kid);
        } else {
          keys[k.kid] = k;
        }
      }
      // Two usable keys under one kid make key selection ambiguous
      // (TEST-004): trust neither.
      ambiguous.forEach(keys.remove);
      _keys = keys;
      _everLoaded = true;
      _lastFailed = false;
    } catch (cause) {
      _lastFailed = true;
      throw JwksException(JwksFailure.unavailable, cause: cause);
    }
  }
}
