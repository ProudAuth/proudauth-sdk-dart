/// Multi-issuer applications (INT-009): tokens from several explicitly
/// registered issuers, for example one realm per customer. The token's `iss`
/// only selects the registration; that issuer's [Verifier] then checks
/// everything, `iss` included. A validly signed token from any other issuer
/// is refused, even when its subject or email matches a known user.
/// Subjects are unique per issuer only: key application records by
/// (tenant, subject).
library;

import 'dart:convert';

import 'cancel.dart';
import 'claims.dart';
import 'errors.dart';
import 'internal/base64url.dart';
import 'middleware.dart';
import 'verifier.dart';

/// One trusted issuer and the application's tenant for its tokens.
final class IssuerRegistration {
  const IssuerRegistration({required this.verifier, required this.tenant});

  /// A verifier configured for exactly this issuer.
  final Verifier verifier;

  /// The application's own tenant for tokens of this issuer.
  final String tenant;
}

/// Verified claims with the tenant of their issuer.
final class TenantClaims {
  const TenantClaims(this.claims, this.tenant);
  final Claims claims;
  final String tenant;
}

/// Verifies tokens of several registered issuers.
final class MultiIssuerVerifier implements Authenticator {
  /// Registrations keyed by exact issuer URL. Throws [ArgumentError] unless
  /// every registration has a tenant and a verifier for exactly that issuer.
  MultiIssuerVerifier(Map<String, IssuerRegistration> registrations)
      : _issuers = Map.unmodifiable(registrations) {
    for (final e in registrations.entries) {
      if (e.key.isEmpty ||
          e.value.tenant.isEmpty ||
          e.value.verifier.issuer != e.key) {
        throw ArgumentError(
            'verifier: each registration needs a tenant and a verifier configured for exactly that issuer');
      }
    }
    if (registrations.isEmpty) {
      throw ArgumentError('verifier: register at least one issuer');
    }
  }

  final Map<String, IssuerRegistration> _issuers;

  /// Verifies a token and returns its claims with the issuer's tenant.
  Future<TenantClaims> verifyTenant(String raw,
      {CancelToken? cancelToken}) async {
    final reg = _issuers[_unverifiedIssuer(raw)];
    if (reg == null) throw VerifierException(VerifierErrorCode.issuer);
    final claims = await reg.verifier.verify(raw, cancelToken: cancelToken);
    return TenantClaims(claims, reg.tenant);
  }

  /// [Authenticator] interface; prefer [verifyTenant] where tenants matter.
  @override
  Future<Claims> authenticate(String raw, {CancelToken? cancelToken}) async =>
      (await verifyTenant(raw, cancelToken: cancelToken)).claims;
}

/// Reads iss only to choose a verifier; nothing else in the unverified
/// payload is used.
String _unverifiedIssuer(String raw) {
  if (raw.length > 16 << 10) {
    throw VerifierException(VerifierErrorCode.malformed);
  }
  final parts = raw.split('.');
  if (parts.length != 3) throw VerifierException(VerifierErrorCode.malformed);
  Object? iss;
  try {
    final payload = jsonDecode(
        utf8.decode(decodeBase64UrlLenient(parts[1]), allowMalformed: true));
    if (payload is Map<String, Object?>) iss = payload['iss'];
  } catch (e) {
    throw VerifierException(VerifierErrorCode.malformed, cause: e);
  }
  if (iss is! String || iss.isEmpty) {
    throw VerifierException(VerifierErrorCode.malformed);
  }
  return iss;
}
