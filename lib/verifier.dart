/// Offline JWT access-token verification for resource servers (SDK-001):
/// [Verifier], [MultiIssuerVerifier], the verified [Claims] and the
/// framework-neutral request helpers ([bearerToken], [authorizeBearer],
/// [challenge]).
///
/// Offline verification cannot observe revocation before expiry (SES-023).
/// Use `package:proudauth_sdk/introspection.dart` (strict-online) where that
/// exposure is unacceptable, and always for support (impersonation) tokens.
library;

export 'src/cancel.dart' show CancelToken;
export 'src/claims.dart' show Actor, Claims, supportTokenKind;
export 'src/errors.dart' show VerifierErrorCode, VerifierException;
export 'src/internal/jws.dart' show supportedAlgorithms;
export 'src/middleware.dart'
    show
        AuthAccepted,
        AuthChallenge,
        AuthOutcome,
        AuthRejected,
        Authenticator,
        authenticateAuthorization,
        authorizeBearer,
        bearerToken,
        bearerTokenFromValues,
        challenge;
export 'src/multi_issuer.dart'
    show IssuerRegistration, MultiIssuerVerifier, TenantClaims;
export 'src/verifier.dart' show Verifier, defaultAcceptedKinds, maxClockSkew;
