/// Verification error categories. They are stable, safe to log and never
/// contain token material, secrets or claim values (SDK-008).
///
/// [value] is the category string shared with the Go and Node.js SDKs and the
/// shared fixtures (`sdk/fixtures`).
enum VerifierErrorCode {
  missingToken('missing_token', 'missing bearer token'),
  invalidRequest(
    'invalid_request',
    'bearer token must be sent in the Authorization header, not the query string',
  ),
  malformed('malformed', 'malformed token'),
  tooLarge('too_large', 'token too large'),
  duplicateClaim('duplicate_claim', 'duplicate JSON member'),
  tokenType('token_type', 'wrong token type'),
  algorithm('algorithm', 'algorithm not allowed'),
  unknownKey('unknown_key', 'unknown signing key'),
  signature('signature', 'invalid signature'),
  issuer('issuer', 'untrusted issuer'),
  audience('audience', 'wrong audience'),
  expired('expired', 'token expired'),
  notYetValid('not_yet_valid', 'token not yet valid'),
  futureIssued('future_issued', 'token issued in the future'),
  tokenKind('token_kind', 'token kind not accepted'),
  senderConstraint('sender_constraint', 'sender constraint not satisfied'),
  inactive('inactive', 'token is not active'),
  unavailable('unavailable', 'verification dependency unavailable'),
  organization('organization', 'organization mismatch'),
  scope('scope', 'required scope missing'),
  supportPolicy(
    'support_policy',
    'support access not permitted for this operation',
  ),
  contract('contract', 'support contract not satisfied (auditor required)'),
  staleState(
    'stale_state',
    'revocation state is older than the configured bound',
  ),
  revoked('revoked', 'session or subject was revoked');

  const VerifierErrorCode(this.value, this.description);

  /// The category string, e.g. `missing_token` (same as the Node.js SDK's
  /// `VerifierError.code`).
  final String value;

  /// A short, fixed description without token material.
  final String description;

  /// Looks up a code by its category string.
  static VerifierErrorCode? fromValue(String value) {
    for (final c in values) {
      if (c.value == value) return c;
    }
    return null;
  }
}

/// A verification failure (the Node.js SDK's `VerifierError`).
///
/// [message] is `verifier: <description>`; it never contains token material,
/// secrets or claim values.
class VerifierException implements Exception {
  /// Creates an exception for [code]; [cause] is kept for diagnostics.
  VerifierException(this.code, {this.cause});

  /// The stable error category.
  final VerifierErrorCode code;

  /// The underlying failure, when there is one (for example a network error
  /// behind `unavailable`). It never carries token material either.
  final Object? cause;

  /// `verifier: <description>`.
  String get message => 'verifier: ${code.description}';

  @override
  String toString() => message;
}
