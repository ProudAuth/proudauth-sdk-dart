/// Strict-online token validation (§13.2, SDK-002) with [Introspector], and
/// the downstream support-access contract (§16.2) with [SupportGuard].
///
/// Every call consults the identity provider through RFC 7662
/// introspection. There is no positive cache, and any failure denies with
/// an `unavailable` error rather than downgrading to offline checks
/// (TEST-035).
library;

export 'src/cancel.dart' show CancelToken;
export 'src/claims.dart' show Actor, Claims, supportTokenKind;
export 'src/errors.dart' show VerifierErrorCode, VerifierException;
export 'src/introspection.dart'
    show
        Introspector,
        SupportAuditor,
        SupportDenyReason,
        SupportEvent,
        SupportGuard,
        defaultOnlineKinds,
        isProtectedOperation,
        isWriteOperation,
        protectedOperations,
        writeSegments;
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
