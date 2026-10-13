/// Small HTTP helpers shared by the SDK modules, the Dart counterpart of the
/// Node.js SDK's `internal/http.ts`. Nothing here logs, and no helper
/// includes request or response bodies in errors (SDK-008).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../cancel.dart';

/// The request deadline passed.
final class HttpTimeoutException implements Exception {
  const HttpTimeoutException();
  @override
  String toString() => 'request timed out';
}

/// The caller's [CancelToken] was cancelled.
final class HttpCancelledException implements Exception {
  const HttpCancelledException();
  @override
  String toString() => 'request cancelled';
}

/// The response body exceeded the configured limit.
final class BodyTooLargeException implements Exception {
  const BodyTooLargeException();
  @override
  String toString() => 'response body exceeds the configured limit';
}

/// A completed exchange.
final class HttpResult {
  HttpResult(this.status, this.headers, this.body);

  final int status;

  /// Response headers with lower-case names (repeated headers joined by
  /// commas, as package:http does).
  final Map<String, String> headers;

  /// The body, or empty when it was not read.
  final Uint8List body;
}

bool _always(int status) => true;

/// Sends one request without following redirects (a 3xx is returned as a
/// response) and reads at most [maxBodyBytes] of the body, all within
/// [timeout]. [cancelToken] lets the caller stop early.
///
/// The body is read only when [readBody] returns true for the status;
/// otherwise it is discarded.
///
/// Throws [HttpTimeoutException], [HttpCancelledException],
/// [BodyTooLargeException] or the transport's own exception.
Future<HttpResult> sendRequest(
  http.Client client, {
  required String method,
  required Uri url,
  Map<String, String> headers = const {},
  List<int>? body,
  required Duration timeout,
  CancelToken? cancelToken,
  required int maxBodyBytes,
  bool Function(int status) readBody = _always,
}) {
  final abort = Completer<void>();
  final result = Completer<HttpResult>();
  StreamSubscription<List<int>>? sub;
  void Function()? removeCancel;

  void fail(Object error, [StackTrace? stack]) {
    if (!result.isCompleted) result.completeError(error, stack);
    if (!abort.isCompleted) abort.complete();
    final s = sub;
    sub = null;
    if (s != null) unawaited(s.cancel());
  }

  void succeed(HttpResult r) {
    if (!result.isCompleted) result.complete(r);
  }

  final timer = Timer(timeout, () => fail(const HttpTimeoutException()));
  if (cancelToken != null) {
    removeCancel =
        onCancel(cancelToken, () => fail(const HttpCancelledException()));
  }

  if (!result.isCompleted) {
    final req = http.AbortableRequest(method, url, abortTrigger: abort.future)
      ..followRedirects = false
      ..persistentConnection = true;
    req.headers.addAll(headers);
    // bodyBytes (unlike body) leaves the content-type header untouched.
    if (body != null) req.bodyBytes = body;
    unawaited(() async {
      try {
        final res = await client.send(req);
        if (result.isCompleted) {
          unawaited(_discard(res.stream));
          return;
        }
        final status = res.statusCode;
        final resHeaders = res.headers;
        if (!readBody(status)) {
          unawaited(_discard(res.stream));
          succeed(HttpResult(status, resHeaders, Uint8List(0)));
          return;
        }
        final declared = res.contentLength;
        if (declared != null && declared > maxBodyBytes) {
          unawaited(_discard(res.stream));
          fail(const BodyTooLargeException());
          return;
        }
        final builder = BytesBuilder(copy: false);
        sub = res.stream.listen(
          (chunk) {
            builder.add(chunk);
            if (builder.length > maxBodyBytes) {
              fail(const BodyTooLargeException());
            }
          },
          onError: (Object e, StackTrace st) => fail(e, st),
          onDone: () => succeed(HttpResult(
            status,
            resHeaders,
            builder.takeBytes(),
          )),
          cancelOnError: true,
        );
      } catch (e, st) {
        fail(e, st);
      }
    }());
  }

  return result.future.whenComplete(() {
    timer.cancel();
    removeCancel?.call();
  });
}

Future<void> _discard(Stream<List<int>> stream) async {
  try {
    await stream.listen(null, cancelOnError: true).cancel();
  } catch (_) {
    // Nothing to do: the body is not needed.
  }
}

/// application/x-www-form-urlencoded encoding of one value, equivalent to
/// Go's url.QueryEscape (RFC 6749 §2.3.1 requires it for client credentials
/// in Basic auth).
String formEncode(String value) => Uri.encodeComponent(value)
    .replaceAllMapped(
      RegExp(r"[!'()*]"),
      (m) => '%${m[0]!.codeUnitAt(0).toRadixString(16).toUpperCase()}',
    )
    .replaceAll('%20', '+');

/// Encodes a form body (null values are skipped).
String formBody(Map<String, String?> fields) => fields.entries
    .where((e) => e.value != null)
    .map((e) => '${formEncode(e.key)}=${formEncode(e.value!)}')
    .join('&');

/// client_secret_basic Authorization header value (RFC 6749 §2.3.1).
String basicAuthorization(String clientId, String clientSecret) =>
    'Basic ${base64.encode(utf8.encode('${formEncode(clientId)}:${formEncode(clientSecret)}'))}';

/// Validates an absolute http(s) URL without credentials; throws
/// [ArgumentError] with `<prefix>: <what> ...` otherwise.
Uri requireHttpUrl(String? value, String what, String prefix) {
  if (value == null || value.isEmpty) {
    throw ArgumentError('$prefix: $what is required');
  }
  final u = Uri.tryParse(value);
  if (u == null || !u.hasScheme) {
    throw ArgumentError('$prefix: $what must be an absolute URL');
  }
  if (u.scheme != 'https' && u.scheme != 'http') {
    throw ArgumentError('$prefix: $what must be an http(s) URL');
  }
  if (u.host.isEmpty) {
    throw ArgumentError('$prefix: $what must be an absolute URL');
  }
  if (u.userInfo.isNotEmpty) {
    throw ArgumentError('$prefix: $what must not contain credentials');
  }
  return u;
}

/// scheme://host:port of an http(s) URL (default ports made explicit).
String originOf(Uri u) => '${u.scheme}://${u.host}:${u.port}';

/// Removes trailing slashes.
String trimTrailingSlashes(String s) {
  var end = s.length;
  while (end > 0 && s.codeUnitAt(end - 1) == 0x2f) {
    end--;
  }
  return s.substring(0, end);
}

/// Reason phrases (Node's `http.STATUS_CODES`), for problem fallbacks and
/// challenge bodies.
const Map<int, String> statusText = {
  100: 'Continue',
  101: 'Switching Protocols',
  200: 'OK',
  201: 'Created',
  202: 'Accepted',
  204: 'No Content',
  300: 'Multiple Choices',
  301: 'Moved Permanently',
  302: 'Found',
  303: 'See Other',
  304: 'Not Modified',
  307: 'Temporary Redirect',
  308: 'Permanent Redirect',
  400: 'Bad Request',
  401: 'Unauthorized',
  402: 'Payment Required',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  406: 'Not Acceptable',
  408: 'Request Timeout',
  409: 'Conflict',
  410: 'Gone',
  411: 'Length Required',
  412: 'Precondition Failed',
  413: 'Payload Too Large',
  414: 'URI Too Long',
  415: 'Unsupported Media Type',
  416: 'Range Not Satisfiable',
  417: 'Expectation Failed',
  418: "I'm a Teapot",
  421: 'Misdirected Request',
  422: 'Unprocessable Entity',
  423: 'Locked',
  424: 'Failed Dependency',
  425: 'Too Early',
  426: 'Upgrade Required',
  428: 'Precondition Required',
  429: 'Too Many Requests',
  431: 'Request Header Fields Too Large',
  451: 'Unavailable For Legal Reasons',
  500: 'Internal Server Error',
  501: 'Not Implemented',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
  505: 'HTTP Version Not Supported',
  507: 'Insufficient Storage',
  508: 'Loop Detected',
  511: 'Network Authentication Required',
};
