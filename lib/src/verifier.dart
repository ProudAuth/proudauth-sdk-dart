/// Offline JWT access-token verification for resource servers (SDK-001), a
/// port of the Node.js SDK's `verifier.ts`.
library;

import 'dart:convert';

import 'package:http/http.dart' as http;

import 'cancel.dart';
import 'claims.dart';
import 'errors.dart';
import 'internal/http.dart';
import 'internal/jwks.dart';
import 'internal/jws.dart';
import 'middleware.dart';

/// Token kinds accepted offline by default.
const List<String> defaultAcceptedKinds = [
  'user_access',
  'service_access',
  'exchange_access',
];

/// The largest accepted clock tolerance.
const Duration maxClockSkew = Duration(seconds: 60);

/// Verifies JWT access tokens offline with the §14.4 algorithm: a
/// preconfigured trusted issuer (checked before any key fetch), strict
/// parsing with duplicate-member rejection, explicit `at+jwt` typing, an
/// asymmetric algorithm allowlist, key IDs resolved only from that issuer's
/// configured key set with bounded, coalesced refreshes, exact issuer and
/// audience checks, and fail-closed errors.
///
/// Offline verification cannot observe revocation before expiry (SES-023): a
/// revoked session's access token keeps working until `exp` plus the clock
/// skew. Use the strict-online `Introspector` where that exposure is
/// unacceptable, and always for support (impersonation) tokens.
final class Verifier implements Authenticator {
  /// Creates a verifier. Throws [ArgumentError] for an unsafe configuration.
  ///
  /// - [issuer]: the exact trusted issuer. Tokens from any other issuer are
  ///   rejected without fetching anything (TEST-003).
  /// - [audience]: this API's registered audience.
  /// - [jwksUrl]: defaults to `<issuer>/jwks`. Never taken from a token (no
  ///   jku/x5u).
  /// - [algorithms]: asymmetric allowlist; default RS256, PS256, ES256,
  ///   EdDSA. "none" and HS* are refused.
  /// - [clockSkew]: tolerance for exp/nbf/iat (default 30 s, at most 60 s).
  /// - [acceptedKinds]: accepted `token_kind` values (default user_access,
  ///   service_access, exchange_access). impersonation_access is refused:
  ///   support tokens are opaque and must be validated online by the
  ///   `SupportGuard`.
  /// - [minRefreshInterval]: minimum spacing of JWKS refreshes triggered by
  ///   unknown key IDs (default 30 s, at least 1 s).
  /// - [maxTokenBytes]: maximum token size (default 8192).
  /// - [timeout]: JWKS request timeout (default 5 s).
  /// - [httpClient]: custom client (proxies, tests); [close] does not close
  ///   it.
  /// - [now]: clock (tests).
  factory Verifier({
    required String issuer,
    required String audience,
    String? jwksUrl,
    List<String>? algorithms,
    Duration clockSkew = const Duration(seconds: 30),
    List<String>? acceptedKinds,
    Duration minRefreshInterval = const Duration(seconds: 30),
    int maxTokenBytes = 8192,
    Duration timeout = const Duration(seconds: 5),
    http.Client? httpClient,
    DateTime Function()? now,
  }) {
    const prefix = 'verifier';
    if (issuer.isEmpty || audience.isEmpty) {
      throw ArgumentError('verifier: issuer and audience are required');
    }
    final url = requireHttpUrl(
        jwksUrl ?? '${trimTrailingSlashes(issuer)}/jwks', 'jwksUrl', prefix);
    final algs = resolveAlgorithms(algorithms, prefix);
    if (clockSkew.isNegative) {
      throw ArgumentError(
          'verifier: clock skew must be a non-negative duration');
    }
    if (clockSkew > maxClockSkew) {
      throw ArgumentError('verifier: clock skew must be at most 60s');
    }
    final kinds = acceptedKinds == null || acceptedKinds.isEmpty
        ? defaultAcceptedKinds
        : acceptedKinds;
    if (kinds.contains(supportTokenKind)) {
      throw ArgumentError(
          'verifier: impersonation_access cannot be verified offline; use the SupportGuard (strict-online)');
    }
    if (minRefreshInterval < const Duration(seconds: 1)) {
      throw ArgumentError('verifier: minRefreshInterval must be at least 1s');
    }
    if (maxTokenBytes <= 0) {
      throw ArgumentError('verifier: maxTokenBytes must be a positive integer');
    }
    if (timeout <= Duration.zero) {
      throw ArgumentError('verifier: timeout must be positive');
    }
    final clock = now ?? DateTime.now;
    final client = httpClient ?? http.Client();
    return Verifier._(
      issuer,
      audience,
      algs,
      clockSkew,
      Set.unmodifiable(kinds),
      maxTokenBytes,
      clock,
      client,
      httpClient == null,
      JwksCache(
        url: url,
        client: client,
        timeout: timeout,
        minRefreshInterval: minRefreshInterval,
        now: clock,
      ),
    );
  }

  Verifier._(
    this._issuer,
    this._audience,
    this._algorithms,
    this._skew,
    this._acceptedKinds,
    this._maxTokenBytes,
    this._now,
    this._client,
    this._ownsClient,
    this._jwks,
  );

  final String _issuer;
  final String _audience;
  final Set<String> _algorithms;
  final Duration _skew;
  final Set<String> _acceptedKinds;
  final int _maxTokenBytes;
  final DateTime Function() _now;
  final http.Client _client;
  final bool _ownsClient;
  final JwksCache _jwks;

  /// How many JWKS fetches occurred (diagnostics and tests).
  int get fetchCount => _jwks.fetchCount;

  /// The configured issuer.
  String get issuer => _issuer;

  /// The configured audience.
  String get audience => _audience;

  /// Closes the HTTP client the verifier created (not one passed in).
  void close() {
    if (_ownsClient) _client.close();
  }

  /// Verifies a JWT access token offline. Throws a [VerifierException].
  ///
  /// [cancelToken] lets this caller stop waiting for a key-set fetch
  /// (`unavailable`); the shared fetch continues for other callers.
  Future<Claims> verify(String raw, {CancelToken? cancelToken}) async {
    if (raw.isEmpty) throw VerifierException(VerifierErrorCode.missingToken);
    if (raw.length > _maxTokenBytes ||
        utf8.encode(raw).length > _maxTokenBytes) {
      throw VerifierException(VerifierErrorCode.tooLarge);
    }
    final ParsedJws jws;
    try {
      jws = parseCompactJws(raw);
    } on JwsParseException catch (e) {
      throw VerifierException(e.reason == JwsFailure.duplicate
          ? VerifierErrorCode.duplicateClaim
          : VerifierErrorCode.malformed);
    }
    final header = jws.header;
    final payload = jws.payload;

    // Check the issuer before any key lookup so unrelated issuers never
    // trigger fetches.
    if (payload['iss'] != _issuer) {
      throw VerifierException(VerifierErrorCode.issuer);
    }

    // No JOSE extensions are understood, so a critical one cannot be honoured.
    if (header.containsKey('crit')) {
      throw VerifierException(VerifierErrorCode.malformed);
    }
    final alg = header['alg'];
    if (alg is! String || !_algorithms.contains(alg)) {
      throw VerifierException(VerifierErrorCode.algorithm);
    }
    final typHeader = header['typ'];
    final typ = typHeader is String ? typHeader.toLowerCase() : '';
    if (typ != 'at+jwt' && typ != 'application/at+jwt') {
      // e.g. an ID token sent to an API (TEST-002)
      throw VerifierException(VerifierErrorCode.tokenType);
    }
    final kid = header['kid'];
    if (kid is! String || kid.isEmpty) {
      throw VerifierException(VerifierErrorCode.unknownKey);
    }

    final VerificationKey key;
    try {
      key = await _jwks.getKey(kid, cancelToken);
    } on JwksException catch (e) {
      if (e.reason == JwksFailure.unknownKey) {
        throw VerifierException(VerifierErrorCode.unknownKey);
      }
      throw VerifierException(VerifierErrorCode.unavailable, cause: e);
    }
    if (key.alg != null && key.alg != alg) {
      throw VerifierException(VerifierErrorCode.algorithm);
    }
    if (!verifySignature(alg, key.material, jws.signingInput, jws.signature)) {
      throw VerifierException(VerifierErrorCode.signature);
    }
    return _claims(payload);
  }

  /// Implements [Authenticator] for offline verification.
  @override
  Future<Claims> authenticate(String raw, {CancelToken? cancelToken}) =>
      verify(raw, cancelToken: cancelToken);

  Claims _claims(Map<String, Object?> p) {
    String str(String k) {
      final v = p[k];
      if (v == null) return '';
      if (v is! String) throw VerifierException(VerifierErrorCode.malformed);
      return v;
    }

    num? number(String k) {
      final v = p[k];
      if (v == null) return null;
      if (v is! num || !v.isFinite) {
        throw VerifierException(VerifierErrorCode.malformed);
      }
      return v;
    }

    if (str('iss') != _issuer) {
      throw VerifierException(VerifierErrorCode.issuer);
    }

    final aud = p['aud'];
    final List<String> audiences;
    if (aud is String) {
      audiences = [aud];
    } else if (aud == null) {
      audiences = const [];
    } else if (aud is List<Object?> && aud.every((a) => a is String)) {
      audiences = aud.cast<String>();
    } else {
      throw VerifierException(VerifierErrorCode.malformed);
    }
    // Exactly one audience, equal to this API's (narrow audiences, TOK-007,
    // TEST-001).
    if (audiences.length != 1 || audiences[0] != _audience) {
      throw VerifierException(VerifierErrorCode.audience);
    }

    final nowSec = _now().microsecondsSinceEpoch / 1e6;
    final skewSec = _skew.inMicroseconds / 1e6;
    final exp = number('exp');
    final nbf = number('nbf');
    final iat = number('iat');
    if (exp == null || nowSec > exp + skewSec) {
      throw VerifierException(VerifierErrorCode.expired);
    }
    if (nbf != null && nowSec + skewSec < nbf) {
      throw VerifierException(VerifierErrorCode.notYetValid);
    }
    if (iat != null && iat > nowSec + skewSec) {
      throw VerifierException(VerifierErrorCode.futureIssued);
    }

    final subject = str('sub');
    final clientId = str('client_id');
    final jti = str('jti');
    final tokenKind = str('token_kind');
    if (subject.isEmpty ||
        clientId.isEmpty ||
        jti.isEmpty ||
        !_acceptedKinds.contains(tokenKind)) {
      throw VerifierException(VerifierErrorCode.tokenKind);
    }
    final scope = str('scope');
    final authTime = number('auth_time');
    final act = p['act'];
    final actor = act == null ? null : _parseActorStrict(act, 0);
    final orgId = str('org_id');
    final sessionId = str('sid');
    final acr = str('acr');
    final authzVersion = number('authz_version');
    if (p.containsKey('cnf')) {
      throw VerifierException(VerifierErrorCode.senderConstraint);
    }
    return Claims(
      issuer: _issuer,
      subject: subject,
      audience: _audience,
      clientId: clientId,
      scopes: scope.split(_whitespace).where((s) => s.isNotEmpty),
      orgId: orgId,
      sessionId: sessionId,
      tokenKind: tokenKind,
      jti: jti,
      issuedAt: iat != null ? dateFromSeconds(iat) : null,
      expiry: dateFromSeconds(exp),
      authTime:
          authTime != null && authTime > 0 ? dateFromSeconds(authTime) : null,
      acr: acr,
      authzVersion: authzVersion == null ? 0 : clampToInt(authzVersion),
      actor: actor,
      online: false,
    );
  }
}

final RegExp _whitespace = RegExp(r'\s+');

Actor _parseActorStrict(Object? v, int depth) {
  if (depth > 16 || v is! Map<String, Object?>) {
    throw VerifierException(VerifierErrorCode.malformed);
  }
  final sub = v['sub'];
  final iss = v['iss'];
  if (sub is! String || (v.containsKey('iss') && iss is! String)) {
    throw VerifierException(VerifierErrorCode.malformed);
  }
  final act = v['act'];
  return Actor(
    subject: sub,
    issuer: iss as String?,
    act: act == null ? null : _parseActorStrict(act, depth + 1),
  );
}
