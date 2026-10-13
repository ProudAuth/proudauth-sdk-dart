/// `dart:io` adapter (SDK-011): authenticates [HttpRequest]s with any
/// [Authenticator] and writes RFC 6750 responses. The handler only runs
/// with verified claims.
library;

import 'dart:async';
import 'dart:io';

import 'cancel.dart';
import 'claims.dart';
import 'errors.dart';
import 'introspection.dart';
import 'middleware.dart';

final Expando<Claims> _claims = Expando<Claims>('proudauth claims');

/// The claims attached to [request] by [protect] or [protectOperation], or
/// null.
Claims? claimsOf(HttpRequest request) => _claims[request];

/// Extracts the bearer token of [request] (from the `Authorization` header
/// only; `access_token` in the query string is refused) and authenticates
/// it. Throws a [VerifierException].
Future<Claims> authenticateHttpRequest(
  Authenticator authenticator,
  HttpRequest request, {
  CancelToken? cancelToken,
}) {
  final String raw;
  try {
    raw = bearerTokenFromValues(
      request.headers[HttpHeaders.authorizationHeader],
      requestUri: request.uri,
    );
  } catch (e) {
    return Future.error(e);
  }
  return authenticator.authenticate(raw, cancelToken: cancelToken);
}

/// Writes [ch] (status, challenge header, `cache-control: no-store`, a
/// plain-text body without token material) and closes the response. Does
/// nothing when the headers were already sent.
Future<void> sendChallenge(HttpResponse response, AuthChallenge ch) async {
  try {
    response.statusCode = ch.status;
    ch.responseHeaders.forEach(response.headers.set);
    response.write(ch.body);
  } on StateError {
    // Headers already sent: the response is committed.
  } on HttpException {
    // Same, reported by some dart:io versions.
  }
  try {
    await response.close();
  } catch (_) {
    // Already closed or the connection is gone.
  }
}

/// A `dart:io` request handler.
typedef HttpRequestHandler = FutureOr<void> Function(HttpRequest request);

/// Wraps a handler: it runs only with verified claims (also available via
/// [claimsOf]); otherwise the RFC 6750 response is written and the handler
/// is skipped. With [requiredScopes], a token without them gets
/// `403 insufficient_scope` (and the scopes in the challenge).
///
/// [onError] receives authentication failures for telemetry (categories
/// only); [onHandlerError] is called when [handler] throws (the response
/// then becomes a 500 when nothing was sent yet).
HttpRequestHandler protect(
  Authenticator authenticator,
  FutureOr<void> Function(HttpRequest request, Claims claims) handler, {
  List<String> requiredScopes = const [],
  String? realm,
  void Function(Object error, HttpRequest request)? onError,
  void Function(Object error, StackTrace stack, HttpRequest request)?
      onHandlerError,
}) {
  return (request) async {
    final outcome = await authorizeBearer(
      authenticator,
      authorizationValues:
          request.headers[HttpHeaders.authorizationHeader] ?? const [],
      requestUri: request.uri,
      requiredScopes: requiredScopes,
      realm: realm,
      onError: onError == null ? null : (e) => onError(e, request),
    );
    switch (outcome) {
      case AuthRejected(:final challenge):
        await sendChallenge(request.response, challenge);
      case AuthAccepted(:final claims):
        _claims[request] = claims;
        try {
          await handler(request, claims);
        } catch (e, st) {
          try {
            onHandlerError?.call(e, st, request);
          } catch (_) {
            // ignore reporting failures
          }
          try {
            request.response.statusCode = HttpStatus.internalServerError;
          } on StateError {
            // Already committed; just end it.
          } on HttpException {
            // Same.
          }
          try {
            await request.response.close();
          } catch (_) {
            // The connection is gone.
          }
        }
    }
  };
}

/// [protect] for one route operation of an API that serves both ordinary
/// and support requests, using [SupportGuard.authorizeAny]: 401 invalid
/// token, 403 support policy, 503 unavailable or audit failure.
HttpRequestHandler protectOperation(
  SupportGuard guard,
  FutureOr<void> Function(HttpRequest request, Claims claims) handler, {
  required String operation,
  required bool read,
  String? realm,
  void Function(Object error, HttpRequest request)? onError,
  void Function(Object error, StackTrace stack, HttpRequest request)?
      onHandlerError,
}) =>
    protect(
      guard.operation(operation, read: read),
      handler,
      realm: realm,
      onError: onError,
      onHandlerError: onHandlerError,
    );
