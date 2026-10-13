import 'errors.dart';

/// RFC 8693 actor claim ("act"): who is acting on behalf of the subject.
final class Actor {
  const Actor({required this.subject, this.issuer, this.act});

  /// act.sub
  final String subject;

  /// act.iss, when present.
  final String? issuer;

  /// A nested actor (delegation chains).
  final Actor? act;
}

/// The verified security context of one request. Instances are immutable.
///
/// Organization and object ownership remain resource-server decisions:
/// compare [orgId] with the organization of the resource taken from your own
/// data ([requireOrganization]), never with an identifier from the request.
final class Claims {
  Claims({
    required this.issuer,
    required this.subject,
    required this.audience,
    required this.clientId,
    required Iterable<String> scopes,
    required this.orgId,
    required this.sessionId,
    required this.tokenKind,
    required this.jti,
    this.issuedAt,
    this.expiry,
    this.authTime,
    required this.acr,
    required this.authzVersion,
    this.actor,
    this.supportMode = '',
    this.impersonationGrantId = '',
    required this.online,
  }) : scopes = List.unmodifiable(scopes);

  final String issuer;
  final String subject;
  final String audience;
  final String clientId;
  final List<String> scopes;
  final String orgId;
  final String sessionId;
  final String tokenKind;
  final String jti;
  final DateTime? issuedAt;
  final DateTime? expiry;
  final DateTime? authTime;
  final String acr;

  /// Authorization revision; only meaningful when compared with trusted
  /// current state.
  final int authzVersion;
  final Actor? actor;

  /// `read_only` or `allowlisted_write` for support tokens (strict-online
  /// only).
  final String supportMode;
  final String impersonationGrantId;

  /// True when live server state was consulted (introspection).
  final bool online;

  /// Whether the token carries [scope].
  bool hasScope(String scope) => scopes.contains(scope);

  /// Throws a `scope` [VerifierException] unless [scope] is present.
  void requireScope(String scope) => requireScopes([scope]);

  /// Throws a `scope` [VerifierException] unless every listed scope is
  /// present.
  void requireScopes(Iterable<String> required) {
    for (final s in required) {
      if (!hasScope(s)) throw VerifierException(VerifierErrorCode.scope);
    }
  }

  /// Matches the verified organization context with the organization that
  /// owns the requested resource, taken from the service's own trusted data
  /// (§14.4 step 8, TEST-007/008). Throws an `organization`
  /// [VerifierException] on any mismatch, including when either side is
  /// empty.
  void requireOrganization(String resourceOrgId) {
    if (orgId.isEmpty || resourceOrgId.isEmpty || orgId != resourceOrgId) {
      throw VerifierException(VerifierErrorCode.organization);
    }
  }

  /// Whether this is a support (impersonation) request.
  bool get isSupport => tokenKind == supportTokenKind;
}

/// The token kind of support (impersonation) tokens: opaque and
/// strict-online only (IMP-010).
const String supportTokenKind = 'impersonation_access';

/// Seconds since the epoch to a UTC [DateTime], clamped to the representable
/// range (a JWT may carry any finite number).
DateTime dateFromSeconds(num seconds) {
  const maxMs = 8640000000000000;
  final ms = seconds * 1000;
  if (ms >= maxMs) {
    return DateTime.fromMillisecondsSinceEpoch(maxMs, isUtc: true);
  }
  if (ms <= -maxMs) {
    return DateTime.fromMillisecondsSinceEpoch(-maxMs, isUtc: true);
  }
  return DateTime.fromMicrosecondsSinceEpoch((seconds * 1000000).round(),
      isUtc: true);
}

/// A finite number as an int, truncated and clamped to the safe integer
/// range.
int clampToInt(num v) {
  const max = 9007199254740991; // 2^53 - 1, exact on every platform
  if (v >= max) return max;
  if (v <= -max) return -max;
  return v.truncate();
}
