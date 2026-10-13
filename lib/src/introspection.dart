/// Strict-online token validation (§13.2, SDK-002) and the downstream
/// support-access contract (§16.2), a port of the Node.js SDK's
/// `introspection.ts`.
///
/// Every call consults the identity provider's authoritative state through
/// RFC 7662 introspection. There is no positive cache, and any failure
/// (network error, timeout, non-200, unparsable response) denies with an
/// `unavailable` error rather than downgrading to offline checks
/// (TEST-035).
library;

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'cancel.dart';
import 'claims.dart';
import 'errors.dart';
import 'internal/http.dart';
import 'internal/json.dart';
import 'middleware.dart';

/// Token kinds the [Introspector] accepts by default (support tokens only
/// via [SupportGuard]).
const List<String> defaultOnlineKinds = [
  'user_access',
  'service_access',
  'exchange_access',
  'api_key',
  'personal_access',
];

/// Introspection responses larger than this are refused (64 KiB).
const int maxIntrospectionResponseBytes = 64 << 10;

/// Strict-online authenticator.
final class Introspector implements Authenticator {
  /// Creates an introspector. Throws [ArgumentError] for an invalid
  /// configuration.
  ///
  /// - [endpoint]: the issuer's introspection endpoint, e.g.
  ///   `<issuer>/oauth/introspect`.
  /// - [clientId], [clientSecret]: this resource server's confidential
  ///   client credentials (client_secret_basic).
  /// - [issuer]: exact expected issuer of introspected tokens.
  /// - [audience]: this API's audience; tokens for any other audience are
  ///   rejected.
  /// - [timeout]: per-request deadline (default 3 s). Timeouts deny.
  /// - [acceptedKinds]: accepted `token_kind` values for [authenticate]
  ///   (default [defaultOnlineKinds]). impersonation_access is refused here:
  ///   support tokens go through [SupportGuard].
  /// - [maxTokenBytes]: longer tokens are rejected without a network call
  ///   (default 8192).
  factory Introspector({
    required String endpoint,
    required String clientId,
    required String clientSecret,
    required String issuer,
    required String audience,
    Duration timeout = const Duration(seconds: 3),
    List<String>? acceptedKinds,
    int maxTokenBytes = 8192,
    http.Client? httpClient,
  }) {
    const prefix = 'introspection';
    final url = requireHttpUrl(endpoint, 'endpoint', prefix);
    for (final (name, value) in [
      ('clientId', clientId),
      ('clientSecret', clientSecret),
      ('issuer', issuer),
      ('audience', audience),
    ]) {
      if (value.isEmpty) {
        throw ArgumentError('introspection: $name is required');
      }
    }
    if (timeout <= Duration.zero) {
      throw ArgumentError('introspection: timeout must be positive');
    }
    final kinds = acceptedKinds == null || acceptedKinds.isEmpty
        ? defaultOnlineKinds
        : acceptedKinds;
    if (kinds.contains(supportTokenKind)) {
      throw ArgumentError(
          'introspection: impersonation_access must be handled by a SupportGuard, not accepted as an ordinary kind');
    }
    if (maxTokenBytes <= 0) {
      throw ArgumentError('introspection: maxTokenBytes must be positive');
    }
    return Introspector._(
      url,
      basicAuthorization(clientId, clientSecret),
      issuer,
      audience,
      timeout,
      Set.unmodifiable(kinds),
      maxTokenBytes,
      httpClient ?? http.Client(),
      httpClient == null,
    );
  }

  Introspector._(
    this._endpoint,
    this._authorization,
    this._issuer,
    this._audience,
    this._timeout,
    this._kinds,
    this._maxTokenBytes,
    this._client,
    this._ownsClient,
  );

  final Uri _endpoint;
  final String _authorization;
  final String _issuer;
  final String _audience;
  final Duration _timeout;
  final Set<String> _kinds;
  final int _maxTokenBytes;
  final http.Client _client;
  final bool _ownsClient;

  String get issuer => _issuer;

  String get audience => _audience;

  /// Closes the HTTP client the introspector created (not one passed in).
  void close() {
    if (_ownsClient) _client.close();
  }

  /// Introspects and checks issuer and audience; no token-kind policy.
  Future<Claims> _introspect(String raw, CancelToken? cancelToken) async {
    if (raw.isEmpty) throw VerifierException(VerifierErrorCode.missingToken);
    if (utf8.encode(raw).length > _maxTokenBytes) {
      throw VerifierException(VerifierErrorCode.tooLarge);
    }
    final Object? m;
    try {
      final res = await sendRequest(
        _client,
        method: 'POST',
        url: _endpoint,
        headers: {
          'authorization': _authorization,
          'content-type': 'application/x-www-form-urlencoded',
          'accept': 'application/json',
        },
        body: utf8.encode(formBody({'token': raw})),
        timeout: _timeout,
        cancelToken: cancelToken,
        maxBodyBytes: maxIntrospectionResponseBytes,
        readBody: (status) => status == 200,
      );
      if (res.status != 200) {
        throw StateError('introspection endpoint returned HTTP ${res.status}');
      }
      m = parseStrictJsonBytes(res.body);
    } catch (cause) {
      throw VerifierException(VerifierErrorCode.unavailable, cause: cause);
    }
    if (m is! Map<String, Object?>) {
      throw VerifierException(VerifierErrorCode.unavailable);
    }
    if (m['active'] != true) {
      throw VerifierException(VerifierErrorCode.inactive);
    }
    final c = _toClaims(m);
    if (c.issuer != _issuer) throw VerifierException(VerifierErrorCode.issuer);
    if (c.audience != _audience) {
      throw VerifierException(VerifierErrorCode.audience);
    }
    return c;
  }

  bool _acceptsKind(String kind) => _kinds.contains(kind);

  /// Verifies a non-support token online. Throws a [VerifierException].
  @override
  Future<Claims> authenticate(String raw, {CancelToken? cancelToken}) async {
    final c = await _introspect(raw, cancelToken);
    if (!_kinds.contains(c.tokenKind)) {
      // A support token presented to an API path that has not implemented
      // the support contract is rejected (IMP-001, TEST-045).
      throw VerifierException(VerifierErrorCode.tokenKind);
    }
    return c;
  }
}

final RegExp _whitespace = RegExp(r'\s+');

Claims _toClaims(Map<String, Object?> m) {
  if (m.containsKey('cnf')) {
    throw VerifierException(VerifierErrorCode.senderConstraint);
  }
  String str(String k) {
    final v = m[k];
    return v is String ? v : '';
  }

  int number(String k) {
    final v = m[k];
    return v is num && v.isFinite ? clampToInt(v) : 0;
  }

  DateTime? date(String k) {
    final v = number(k);
    return v > 0 ? dateFromSeconds(v) : null;
  }

  var audience = '';
  final aud = m['aud'];
  if (aud is String) {
    audience = aud;
  } else if (aud is List<Object?> && aud.length == 1 && aud[0] is String) {
    audience = aud[0]! as String;
  }
  return Claims(
    issuer: str('iss'),
    subject: str('sub'),
    audience: audience,
    clientId: str('client_id'),
    scopes: str('scope').split(_whitespace).where((s) => s.isNotEmpty),
    orgId: str('org_id'),
    sessionId: str('sid'),
    tokenKind: str('token_kind'),
    jti: str('jti'),
    acr: str('acr'),
    authzVersion: number('authz_version'),
    supportMode: str('support_mode'),
    impersonationGrantId: str('impersonation_grant_id'),
    expiry: date('exp'),
    issuedAt: date('iat'),
    authTime: date('auth_time'),
    actor: _parseActorLenient(m['act'], 0),
    online: true,
  );
}

Actor? _parseActorLenient(Object? v, int depth) {
  if (depth > 16 || v is! Map<String, Object?>) return null;
  final sub = v['sub'];
  final iss = v['iss'];
  return Actor(
    subject: sub is String ? sub : '',
    issuer: iss is String ? iss : null,
    act: _parseActorLenient(v['act'], depth + 1),
  );
}

// ---------------------------------------------------------------------------
// Support-access contract
// ---------------------------------------------------------------------------

/// Operations that can never be performed with support access (IMP-012,
/// IMP-013). Each entry is one or more operation-name segments; see
/// [isProtectedOperation] for how they match (the same rule as the Go and
/// Node.js SDKs and the server).
const List<String> protectedOperations = [
  'password.change',
  'password.reset',
  'mfa.change',
  'identifier.change',
  'account.link',
  'credential.export',
  'api_key.create',
  'personal_token.create',
  'consent.modify',
  'idp.admin',
  'payment',
  'refund',
  'ownership.transfer',
  'secret.read',
  'secret',
  'delete',
  'purge',
];

/// Verbs that make an operation a write wherever they appear as a segment
/// of its name, even when the caller declared it a read
/// (`orders.read.update` is a write). Matching is exact per segment.
const List<String> writeSegments = [
  'create', 'add', 'insert', 'update', 'edit', 'modify', 'change', 'set', //
  'put', 'patch', 'write', 'upsert', 'replace', 'delete', 'remove',
  'destroy', 'erase', 'purge', 'archive', 'unarchive', 'restore', 'reset',
  'rotate', 'revoke', 'grant', 'assign', 'unassign', 'link', 'unlink',
  'transfer', 'issue', 'approve', 'reject', 'cancel', 'enable', 'disable',
  'suspend', 'reactivate', 'activate', 'deactivate', 'lock', 'unlock',
  'invite', 'send', 'submit', 'publish', 'unpublish', 'import', 'merge',
  'move', 'rename', 'refund', 'pay', 'execute',
];

final Set<String> _writeSegmentSet = writeSegments.toSet();
final RegExp _separators = RegExp('[.:/]');

/// Normalizes an operation name for classification: trimmed, lowercased,
/// '-' read as '_', split into segments on '.', ':' and '/', empty segments
/// dropped.
List<String> _operationSegments(String operation) => operation
    .trim()
    .toLowerCase()
    .replaceAll('-', '_')
    .split(_separators)
    .where((s) => s.isNotEmpty)
    .toList();

/// One operation segment matches one entry segment, tolerating a simple
/// plural on either side.
bool _segmentMatches(String seg, String entry) =>
    seg == entry || seg == '${entry}s' || '${seg}s' == entry;

/// Whether [entry]'s segments occur as a contiguous run in [segs].
bool _containsRun(List<String> segs, List<String> entry) {
  if (entry.isEmpty || entry.length > segs.length) return false;
  for (var start = 0; start + entry.length <= segs.length; start++) {
    var all = true;
    for (var k = 0; k < entry.length; k++) {
      if (!_segmentMatches(segs[start + k], entry[k])) {
        all = false;
        break;
      }
    }
    if (all) return true;
  }
  return false;
}

/// Whether [operation] touches a protected identity, money or secret
/// operation anywhere in its name under the given list (default
/// [protectedOperations]; a list passed here replaces the defaults): the
/// segments of an entry occur as a contiguous run of the operation's
/// segments, case-insensitively and tolerating simple plurals
/// (`orders.refund`, `refunds.issue`, `payments.create`, `secrets.read`,
/// `orders.purge`, `users.password.change`, `Account.Delete`). An empty
/// operation is treated as protected (deny by default).
bool isProtectedOperation(String operation,
    [List<String> protectedOps = protectedOperations]) {
  final segs = _operationSegments(operation);
  if (segs.isEmpty) return true;
  return protectedOps.any((p) => _containsRun(segs, _operationSegments(p)));
}

/// Whether any segment of [operation] is a write-like verb
/// ([writeSegments]). Such operations are writes even when declared reads.
bool isWriteOperation(String operation) =>
    _operationSegments(operation).any(_writeSegmentSet.contains);

/// Why a support request was denied.
enum SupportDenyReason {
  protectedOperation('protected_operation'),
  writeNotAllowlisted('write_not_allowlisted');

  const SupportDenyReason(this.value);

  /// The string used by the other SDKs and the shared fixtures.
  final String value;
}

/// The actor-aware record a resource must persist for every support request
/// (IMP-006).
final class SupportEvent {
  const SupportEvent({
    required this.grantId,
    required this.actor,
    required this.actorIssuer,
    required this.subject,
    required this.orgId,
    required this.clientId,
    required this.tokenId,
    required this.operation,
    required this.read,
    required this.allowed,
    required this.denyReason,
    required this.at,
  });

  final String grantId;

  /// The real administrator (act.sub).
  final String actor;
  final String? actorIssuer;

  /// The effective customer subject.
  final String subject;
  final String orgId;
  final String clientId;
  final String tokenId;
  final String operation;

  /// Effective classification: false when declared a write or the name
  /// carries a write-like segment.
  final bool read;
  final bool allowed;

  /// Why access was denied, when it was.
  final SupportDenyReason? denyReason;
  final DateTime at;
}

/// Persists support evidence. It is called BEFORE access is granted; if it
/// throws, access is denied. A resource that cannot record the actor must
/// not serve support requests.
abstract class SupportAuditor {
  const SupportAuditor();

  /// An auditor backed by a function.
  const factory SupportAuditor.from(
    FutureOr<void> Function(SupportEvent event, CancelToken? cancelToken)
        record,
  ) = _FunctionAuditor;

  FutureOr<void> recordSupportAccess(SupportEvent event,
      {CancelToken? cancelToken});
}

final class _FunctionAuditor extends SupportAuditor {
  const _FunctionAuditor(this._record);
  final FutureOr<void> Function(SupportEvent, CancelToken?) _record;
  @override
  FutureOr<void> recordSupportAccess(SupportEvent event,
          {CancelToken? cancelToken}) =>
      _record(event, cancelToken);
}

/// Implements the downstream support-access contract: strict-online
/// validation per request, preserved actor identity, read-only default,
/// explicit write allowlist, protected identity operations always denied,
/// and an audit record before access (§16.2, INT-010).
///
/// The contract's two dependencies (an [Introspector] and a
/// [SupportAuditor]) are required constructor arguments, so a guard without
/// an auditor cannot be built.
final class SupportGuard {
  /// - [writeOperations]: operations allowed for tokens in
  ///   `allowlisted_write` mode (IMP-011), matched case-insensitively
  ///   against the whole operation name. Default: none.
  /// - [protectedOperations]: additional protected operations; the defaults
  ///   cannot be removed.
  SupportGuard({
    required Introspector introspector,
    required SupportAuditor auditor,
    List<String> writeOperations = const [],
    List<String> protectedOperations = const [],
  })  : _introspector = introspector,
        _auditor = auditor,
        _writeOps = Set.unmodifiable(
            writeOperations.map((o) => o.trim().toLowerCase())),
        _protected =
            List.unmodifiable([..._defaultProtected, ...protectedOperations]);

  static const List<String> _defaultProtected = protectedOperations;

  final Introspector _introspector;
  final SupportAuditor _auditor;
  final Set<String> _writeOps;
  final List<String> _protected;

  /// Validates a support token for one operation. The audit record is
  /// written before access is granted; if it cannot be written, access is
  /// denied (`unavailable`). Policy denials are audited too and throw
  /// `support_policy`.
  ///
  /// [read] must be true for the operation to count as a read; an operation
  /// whose name carries a write-like segment is a write regardless.
  Future<Claims> authorize(
    String raw,
    String operation, {
    required bool read,
    CancelToken? cancelToken,
  }) async {
    final c = await _introspector._introspect(raw, cancelToken);
    return _decide(c, operation, read, cancelToken);
  }

  /// Single-introspection entry point for APIs that serve both ordinary and
  /// support requests: ordinary tokens are checked against the
  /// Introspector's accepted kinds, support tokens against the full support
  /// contract. The decision is based on the authoritative token_kind, never
  /// on the token's prefix.
  Future<Claims> authorizeAny(
    String raw,
    String operation, {
    required bool read,
    CancelToken? cancelToken,
  }) async {
    final c = await _introspector._introspect(raw, cancelToken);
    if (c.tokenKind == supportTokenKind) {
      return _decide(c, operation, read, cancelToken);
    }
    if (!_introspector._acceptsKind(c.tokenKind)) {
      throw VerifierException(VerifierErrorCode.tokenKind);
    }
    return c;
  }

  /// An [Authenticator] for one route operation using [authorizeAny], for
  /// the request helpers ([authorizeBearer], the `dart:io` adapter): 401
  /// invalid token, 403 support policy, 503 unavailable or audit failure.
  Authenticator operation(String operation, {required bool read}) {
    if (operation.isEmpty) {
      throw ArgumentError('introspection: route operation is required');
    }
    return _OperationAuthenticator(this, operation, read);
  }

  Future<Claims> _decide(
    Claims c,
    String operation,
    bool declaredRead,
    CancelToken? cancelToken,
  ) async {
    final actor = c.actor;
    if (c.tokenKind != supportTokenKind ||
        actor == null ||
        actor.subject.isEmpty ||
        c.impersonationGrantId.isEmpty) {
      // Never grant authority just because an actor claim exists, and never
      // serve a support request whose actor cannot be attributed (IMP-006,
      // TEST-045).
      throw VerifierException(VerifierErrorCode.tokenKind);
    }
    if (operation.trim().isEmpty) {
      throw VerifierException(VerifierErrorCode.supportPolicy);
    }
    final read = declaredRead && !isWriteOperation(operation);
    SupportDenyReason? denyReason;
    if (isProtectedOperation(operation, _protected)) {
      denyReason = SupportDenyReason.protectedOperation;
    } else if (!read &&
        (c.supportMode != 'allowlisted_write' ||
            !_writeOps.contains(operation.trim().toLowerCase()))) {
      denyReason = SupportDenyReason.writeNotAllowlisted;
    }
    final allowed = denyReason == null;
    final event = SupportEvent(
      grantId: c.impersonationGrantId,
      actor: actor.subject,
      actorIssuer: actor.issuer,
      subject: c.subject,
      orgId: c.orgId,
      clientId: c.clientId,
      tokenId: c.jti,
      operation: operation,
      read: read,
      allowed: allowed,
      denyReason: denyReason,
      at: DateTime.now().toUtc(),
    );
    try {
      await _auditor.recordSupportAccess(event, cancelToken: cancelToken);
    } catch (cause) {
      // Durable audit before access (IMP-020): no record, no access.
      throw VerifierException(VerifierErrorCode.unavailable, cause: cause);
    }
    if (!allowed) throw VerifierException(VerifierErrorCode.supportPolicy);
    return c;
  }
}

final class _OperationAuthenticator implements Authenticator {
  _OperationAuthenticator(this._guard, this._operation, this._read);

  final SupportGuard _guard;
  final String _operation;
  final bool _read;

  @override
  Future<Claims> authenticate(String raw, {CancelToken? cancelToken}) => _guard
      .authorizeAny(raw, _operation, read: _read, cancelToken: cancelToken);
}
