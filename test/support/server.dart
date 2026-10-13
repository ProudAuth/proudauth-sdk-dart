// In-process HTTP servers for the tests, the counterpart of the Node.js
// tests' `startServer` helper.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

typedef Handler = FutureOr<void> Function(HttpRequest req, String body);

class TestServer {
  TestServer._(this._server);

  final HttpServer _server;
  int hits = 0;
  final List<String> paths = [];

  String get url => 'http://127.0.0.1:${_server.port}';

  static Future<TestServer> start(Handler handler) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final ts = TestServer._(server);
    server.listen((req) async {
      ts.hits++;
      ts.paths.add(req.uri.toString());
      try {
        final body = await utf8.decoder.bind(req).join();
        await handler(req, body);
      } catch (_) {
        try {
          req.response.statusCode = 500;
        } catch (_) {}
        try {
          await req.response.close();
        } catch (_) {}
      }
    });
    return ts;
  }

  Future<void> close() => _server.close(force: true);
}

/// Writes a JSON response (a String body is sent as is).
Future<void> respondJson(HttpRequest req, int status, Object? body,
    [Map<String, String> headers = const {}]) async {
  req.response.statusCode = status;
  req.response.headers.set('content-type', 'application/json');
  headers.forEach(req.response.headers.set);
  req.response.write(body is String ? body : jsonEncode(body));
  await req.response.close();
}

/// A URL whose port refuses connections (a server started and closed).
Future<String> deadUrl() async {
  final s = await TestServer.start((req, _) => req.response.close());
  final u = s.url;
  await s.close();
  return u;
}

Future<void> sleep(int ms) => Future<void>.delayed(Duration(milliseconds: ms));

/// A mutable clock.
class TestClock {
  TestClock(this.now);
  DateTime now;
  DateTime call() => now;
  void advance(Duration d) => now = now.add(d);
}

DateTime fromSeconds(num s) =>
    DateTime.fromMillisecondsSinceEpoch((s * 1000).round(), isUtc: true);
