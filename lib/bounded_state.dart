/// Bounded-state verification (SDK-002): local verification plus
/// revocations replayed from the session-event stream, failing closed
/// (`stale_state`, 503) when the replayed state is older than its bound.
library;

export 'src/bounded_state.dart'
    show BoundedState, BoundedVerifier, CursorExpiredException;
export 'src/cancel.dart' show CancelToken;
export 'src/claims.dart' show Claims;
export 'src/errors.dart' show VerifierErrorCode, VerifierException;
export 'src/middleware.dart' show Authenticator;
