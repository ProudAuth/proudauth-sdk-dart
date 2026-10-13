/// Framework-neutral request authentication (SDK-011), the counterpart of
/// the Node.js SDK's `middleware.ts`. Every security decision stays in the
/// common Verifier / Introspector / SupportGuard code; these helpers only
/// extract the bearer token, call the authenticator and translate errors
/// into RFC 6750 responses. They deny by default.
///
/// Use them from any framework: pass the `Authorization` header value (and
/// the request URI, so tokens in the query string are refused) and either
/// get verified [Claims] or an [AuthChallenge] to send. The `dart:io`
/// adapter is in `package:proudauth_sdk/io.dart`.
library;

import 'dart:async';

import 'cancel.dart';
import 'claims.dart';
import 'errors.dart';
import 'internal/http.dart' show statusText;

/// Satisfied by `Verifier` (offline), `Introspector` (strict-online),
/// `MultiIssuerVerifier`, `BoundedVerifier` and
/// `SupportGuard.operation(...)`.
abstract interface class Authenticator {
  /// Verifies [raw] and returns its claims, or throws a [VerifierException].
  Future<Claims> authenticate(String raw, {CancelToken? cancelToken});
}

// RFC 6750 §2.1 b64token.
final RegExp _b64token = RegExp(r'^[A-Za-z0-9\-._~+/]+=*$');

/// Extracts a bearer token from one `Authorization` header value.
///
/// Tokens in the query string ([requestUri] carrying `access_token`) are
/// refused with `invalid_request` (TOK-023), even when a header is present.
/// Throws `missing_token` without a usable `Bearer` credential and
/// `malformed` when the credential is not an RFC 6750 b64token.
String bearerToken(String? authorization, {Uri? requestUri}) =>
    bearerTokenFromValues(
      authorization == null ? null : [authorization],
      requestUri: requestUri,
    );

/// Like [bearerToken] for frameworks that expose every value of a repeated
/// header: more than one `Authorization` header is `invalid_request`.
String bearerTokenFromValues(List<String>? authorization, {Uri? requestUri}) {
  if (requestUri != null && _hasAccessTokenParameter(requestUri)) {
    throw VerifierException(VerifierErrorCode.invalidRequest);
  }
  String? h;
  if (authorization != null) {
    if (authorization.length > 1) {
      throw VerifierException(VerifierErrorCode.invalidRequest);
    }
    if (authorization.length == 1) h = authorization.first;
  }
  if (h == null ||
      h.length <= 7 ||
      h.substring(0, 7).toLowerCase() != 'bearer ') {
    throw VerifierException(VerifierErrorCode.missingToken);
  }
  final token = h.substring(7).trim();
  if (token.isEmpty) throw VerifierException(VerifierErrorCode.missingToken);
  if (!_b64token.hasMatch(token)) {
    throw VerifierException(VerifierErrorCode.malformed);
  }
  return token;
}

bool _hasAccessTokenParameter(Uri uri) {
  if (!uri.hasQuery) return false;
  for (final pair in uri.query.split('&')) {
    final eq = pair.indexOf('=');
    final rawKey = eq >= 0 ? pair.substring(0, eq) : pair;
    String key;
    try {
      key = Uri.decodeQueryComponent(rawKey);
    } on ArgumentError {
      key = rawKey;
    } on FormatException {
      key = rawKey;
    }
    if (key == 'access_token') return true;
  }
  return false;
}

/// Extracts the bearer token from an `Authorization` header value and
/// authenticates it.
Future<Claims> authenticateAuthorization(
  Authenticator authenticator,
  String? authorization, {
  Uri? requestUri,
  CancelToken? cancelToken,
}) async {
  final raw = bearerToken(authorization, requestUri: requestUri);
  return authenticator.authenticate(raw, cancelToken: cancelToken);
}

/// An HTTP status and RFC 6750 challenge for a failed request.
final class AuthChallenge {
  const AuthChallenge(this.status, this.headers, [this.error]);

  /// 400, 401, 403, 500 or 503.
  final int status;

  /// `www-authenticate`, when the outcome has a challenge.
  final Map<String, String> headers;

  /// The RFC 6750 error code (`invalid_request`, `invalid_token`,
  /// `insufficient_scope`), when one applies.
  final String? error;

  /// A short plain-text body without token material (the status text).
  String get body => statusText[status] ?? 'Error';

  /// [headers] plus `cache-control: no-store` and a plain-text content type:
  /// everything a failure response should carry.
  Map<String, String> get responseHeaders => {
        ...headers,
        'cache-control': 'no-store',
        'content-type': 'text/plain; charset=utf-8',
      };
}

String _quote(String v) =>
    '"${v.replaceAllMapped(RegExp(r'[\\"]'), (m) => '\\${m[0]}').replaceAll(RegExp('[\r\n]'), ' ')}"';

/// Maps any error to an HTTP status and RFC 6750 challenge:
/// missing token -> 401 without error code; token in query -> 400
/// invalid_request; scope or organization -> 403 insufficient_scope;
/// support policy -> 403; dependency unavailable or stale bounded state ->
/// 503 (fail closed, never a downgrade); support contract -> 500; any other
/// verification failure -> 401 invalid_token; unexpected errors -> 500.
AuthChallenge challenge(
  Object? error, {
  String? realm,
  List<String> scopes = const [],
}) {
  final params = <String>[
    if (realm != null && realm.isNotEmpty) 'realm=${_quote(realm)}',
  ];
  String bearer([List<String> extra = const []]) {
    final all = [...params, ...extra];
    return all.isEmpty ? 'Bearer' : 'Bearer ${all.join(', ')}';
  }

  if (error is! VerifierException) return const AuthChallenge(500, {});
  switch (error.code) {
    case VerifierErrorCode.missingToken:
      return AuthChallenge(401, {'www-authenticate': bearer()});
    case VerifierErrorCode.invalidRequest:
      return AuthChallenge(
        400,
        {
          'www-authenticate': bearer(['error="invalid_request"'])
        },
        'invalid_request',
      );
    case VerifierErrorCode.scope:
      return AuthChallenge(
        403,
        {
          'www-authenticate': bearer([
            'error="insufficient_scope"',
            if (scopes.isNotEmpty) 'scope=${_quote(scopes.join(' '))}',
          ]),
        },
        'insufficient_scope',
      );
    case VerifierErrorCode.organization:
      // The token lacks the organization the resource needs (as in Go).
      return AuthChallenge(
        403,
        {
          'www-authenticate': bearer(['error="insufficient_scope"'])
        },
        'insufficient_scope',
      );
    case VerifierErrorCode.supportPolicy:
      return const AuthChallenge(403, {});
    case VerifierErrorCode.unavailable:
    case VerifierErrorCode.staleState:
      return const AuthChallenge(503, {});
    case VerifierErrorCode.contract:
      return const AuthChallenge(500, {});
    default:
      return AuthChallenge(
        401,
        {
          'www-authenticate': bearer(['error="invalid_token"'])
        },
        'invalid_token',
      );
  }
}

/// The outcome of [authorizeBearer].
sealed class AuthOutcome {
  const AuthOutcome();
}

/// The request carried a valid token (and every required scope).
final class AuthAccepted extends AuthOutcome {
  const AuthAccepted(this.claims);
  final Claims claims;
}

/// The request must be refused with [challenge].
final class AuthRejected extends AuthOutcome {
  const AuthRejected(this.error, this.challenge);

  /// The failure (a [VerifierException] for every expected outcome).
  final Object error;
  final AuthChallenge challenge;
}

/// One call for any framework: extracts the bearer token from
/// [authorization] (one header value) or [authorizationValues] (every value
/// of a repeated header), refuses `access_token` in [requestUri],
/// authenticates it, checks [requiredScopes], and returns either the claims
/// or the challenge to send. [onError] receives every failure for telemetry
/// (categories only; it never sees token material) and cannot change the
/// outcome.
Future<AuthOutcome> authorizeBearer(
  Authenticator authenticator, {
  String? authorization,
  List<String>? authorizationValues,
  Uri? requestUri,
  List<String> requiredScopes = const [],
  String? realm,
  void Function(Object error)? onError,
  CancelToken? cancelToken,
}) async {
  try {
    final raw = authorizationValues != null
        ? bearerTokenFromValues(authorizationValues, requestUri: requestUri)
        : bearerToken(authorization, requestUri: requestUri);
    final claims =
        await authenticator.authenticate(raw, cancelToken: cancelToken);
    claims.requireScopes(requiredScopes);
    return AuthAccepted(claims);
  } catch (e) {
    reportError(onError, e);
    return AuthRejected(
      e,
      challenge(e, realm: realm, scopes: requiredScopes),
    );
  }
}

/// Calls a telemetry callback; its failures never change the outcome.
void reportError(void Function(Object error)? onError, Object error) {
  if (onError == null) return;
  try {
    onError(error);
  } catch (_) {
    // Telemetry must not change the authorization outcome.
  }
}
