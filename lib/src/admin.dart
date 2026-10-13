/// Typed client for the ProudAuth administration and self-service APIs
/// (SDK-003, SDK-007), a port of the Node.js SDK's `admin.ts`. It preserves
/// RFC 9457 problem details, iterates opaque-cursor pages, supports
/// deadlines and cancellation, idempotency keys and If-Match preconditions,
/// sends its version, reports deprecated operations, wraps one-time secrets
/// in [Secret], and never logs request bodies or tokens (SDK-008).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:http/http.dart' as http;

import 'cancel.dart';
import 'internal/http.dart';
import 'internal/json.dart' show decodeUtf8Lenient;

/// This SDK's version, sent with every request.
const String sdkVersion = '0.2.0';

/// A one-time secret returned by the API: a client secret, API key, webhook
/// signing secret, setup or handoff code, download token or recovery code
/// (SDK-007, SDK-008). It never prints or serializes its value: [toString]
/// and [toJson] give `[REDACTED]`; [reveal] returns it for the one place
/// that must store it.
final class Secret {
  const Secret(this._value);

  final String _value;

  /// The secret value.
  String reveal() => _value;

  /// Whether the secret is empty.
  bool get isEmpty => _value.isEmpty;

  @override
  String toString() => _value.isEmpty ? '' : '[REDACTED]';

  /// Used by `jsonEncode`: redacted too.
  String toJson() => toString();
}

/// Response members that carry one-time secrets (the server's list for its
/// idempotency store).
const Set<String> secretMembers = {
  'client_secret', 'client_secrets', 'api_key', 'signing_secret', //
  'setup_token', 'recovery_codes', 'invitation_secret', 'access_token',
  'refresh_token', 'id_token', 'handoff_code', 'download_token', 'token',
  'secret', 'webhook_secrets',
};

Object? _seal(Object? v) {
  if (v is String) return Secret(v);
  if (v is List<Object?>) return v.map(_seal).toList();
  if (v is Map<String, Object?>) return v.map((k, x) => MapEntry(k, _seal(x)));
  return v;
}

/// Replaces secret-bearing values in a decoded response with [Secret],
/// recursively.
Object? wrapSecrets(Object? v) {
  if (v is List<Object?>) return v.map(wrapSecrets).toList();
  if (v is Map<String, Object?>) {
    return v.map((k, x) =>
        MapEntry(k, secretMembers.contains(k) ? _seal(x) : wrapSecrets(x)));
  }
  return v;
}

/// An RFC 9457 problem returned by the API (API-007).
final class ProblemException implements Exception {
  ProblemException(this.status, Map<String, Object?> body, this.headers)
      : extra = Map.unmodifiable(body),
        code = _s(body, 'code').isNotEmpty
            ? _s(body, 'code')
            : statusText[status] ?? 'HTTP $status',
        title = _s(body, 'title'),
        detail = _s(body, 'detail'),
        type = _s(body, 'type').isEmpty ? null : _s(body, 'type'),
        instance = _s(body, 'instance').isEmpty ? null : _s(body, 'instance'),
        errors = Map.unmodifiable(_errors(body)),
        requestId = _s(body, 'request_id').isNotEmpty
            ? _s(body, 'request_id')
            : headers['x-request-id'] ?? '';

  static String _s(Map<String, Object?> b, String k) {
    final v = b[k];
    return v is String ? v : '';
  }

  static Map<String, String> _errors(Map<String, Object?> b) {
    final e = b['errors'];
    if (e is! Map<String, Object?>) return const {};
    return {
      for (final x in e.entries)
        if (x.value is String) x.key: x.value! as String,
    };
  }

  final int status;

  /// Stable machine-readable code.
  final String code;
  final String title;
  final String detail;
  final String? type;
  final String? instance;

  /// Field-level validation errors.
  final Map<String, String> errors;
  final String requestId;

  /// Every member of the problem document, for extension members.
  final Map<String, Object?> extra;

  /// Response headers (lower-case names), e.g. retry-after on 429.
  final Map<String, String> headers;

  String get message {
    final sb = StringBuffer('$status $code: $title');
    if (detail.isNotEmpty) sb.write(' ($detail)');
    for (final e in errors.entries) {
      sb.write(' [${e.key}: ${e.value}]');
    }
    return sb.toString();
  }

  @override
  String toString() => message;
}

/// Transport failure categories.
enum AdminErrorCode {
  timeout('timeout'),
  aborted('aborted'),
  network('network'),
  invalidResponse('invalid_response'),
  tokenSource('token_source');

  const AdminErrorCode(this.value);

  /// The category string of the Node.js SDK.
  final String value;
}

/// Transport-level failures. Never contain request bodies or credentials.
final class AdminRequestException implements Exception {
  AdminRequestException(this.code, this.method, this.path, {this.cause});

  final AdminErrorCode code;
  final String method;

  /// The request path without its query string.
  final String path;
  final Object? cause;

  String get message => 'admin: $method $path failed (${code.value})';

  @override
  String toString() => message;
}

/// Supplies bearer tokens; called once per request.
typedef TokenSource = FutureOr<String> Function(CancelToken cancelToken);

/// A deprecated operation was called (Deprecation and Sunset headers,
/// API-013).
final class DeprecationNotice {
  const DeprecationNotice(
      this.method, this.path, this.deprecation, this.sunset);
  final String method;

  /// The request path without its query string.
  final String path;
  final String deprecation;
  final String? sunset;
}

/// Per-request options.
final class RequestOptions {
  const RequestOptions({
    this.idempotencyKey,
    this.ifMatch,
    this.cancelToken,
    this.timeout,
  });

  /// Idempotency key for safe retries of creates (API-005).
  final String? idempotencyKey;

  /// Optimistic-concurrency precondition (API-010).
  final String? ifMatch;
  final CancelToken? cancelToken;

  /// Overrides the client's default deadline.
  final Duration? timeout;

  RequestOptions _withKey(String key) => RequestOptions(
        idempotencyKey: key,
        ifMatch: ifMatch,
        cancelToken: cancelToken,
        timeout: timeout,
      );
}

/// A decoded response.
final class AdminResponse<T> {
  const AdminResponse({
    required this.status,
    required this.headers,
    required this.etag,
    required this.deprecation,
    required this.sunset,
    required this.data,
  });

  final int status;

  /// Lower-case header names.
  final Map<String, String> headers;

  /// ETag of the returned representation, for If-Match.
  final String? etag;

  /// Set when the server marks the operation deprecated (API-013).
  final String? deprecation;
  final String? sunset;

  /// The decoded body (null for an empty body), with one-time secrets
  /// wrapped in [Secret].
  final T data;
}

/// One page of a cursor-paginated list.
final class Page<T> {
  const Page(this.items, this.nextCursor);
  final List<T> items;
  final String nextCursor;
}

/// A JSON object returned by the API with typed accessors. [data] holds
/// every member (one-time secrets wrapped in [Secret]).
abstract class ApiObject {
  ApiObject(Map<String, Object?> data) : data = Map.unmodifiable(data);

  /// Every member of the object.
  final Map<String, Object?> data;

  /// A member, or null.
  Object? operator [](String key) => data[key];

  String str(String key) {
    final v = data[key];
    return v is String ? v : '';
  }

  int integer(String key) {
    final v = data[key];
    return v is num && v.isFinite ? v.toInt() : 0;
  }

  List<String> strings(String key) {
    final v = data[key];
    return v is List<Object?>
        ? List.unmodifiable(v.whereType<String>())
        : const [];
  }

  @override
  String toString() => '$runtimeType(${jsonEncode(data)})';
}

final class User extends ApiObject {
  User(super.data);
  String get id => str('id');
  String get state => str('state');
  String get displayName => str('display_name');
  List<Map<String, Object?>> get identifiers {
    final v = data['identifiers'];
    return v is List<Object?>
        ? List.unmodifiable(v.whereType<Map<String, Object?>>())
        : const [];
  }

  int get version => integer('version');
}

final class Organization extends ApiObject {
  Organization(super.data);
  String get id => str('id');
  String get slug => str('slug');
  String get displayName => str('display_name');
  String get state => str('state');
  int get version => integer('version');
}

final class Membership extends ApiObject {
  Membership(super.data);
  String get id => str('id');
  String get userId => str('user_id');
  String get state => str('state');
  List<String> get roles => strings('roles');
}

final class Role extends ApiObject {
  Role(super.data);
  String get id => str('id');
  String get name => str('name');
  String get boundaryType => str('boundary_type');
  List<String> get permissions => strings('permissions');
}

final class OAuthClientSummary extends ApiObject {
  OAuthClientSummary(super.data);
  String get id => str('id');
  String get clientId => str('client_id');
  String get name => str('name');
  String get clientType => str('client_type');
  String get state => str('state');
}

final class SessionSummary extends ApiObject {
  SessionSummary(super.data);
  String get id => str('id');
  String get createdAt => str('created_at');
  String get lastActivityAt => str('last_activity_at');
  List<String> get amr => strings('amr');
  String get deviceLabel => str('device_label');
  String get network => str('network');
}

final class InvitationSummary extends ApiObject {
  InvitationSummary(super.data);
  String get id => str('id');
  String get organizationId => str('organization_id');
  String get purpose => str('purpose');
  String get targetEmail => str('target_email');
  String get state => str('state');
  String get deliveryState => str('delivery_state');
  String get expiresAt => str('expires_at');
}

final class SupportGrant extends ApiObject {
  SupportGrant(super.data);
  String get id => str('id');
  String get actorUserId => str('actor_user_id');
  String get targetUserId => str('target_user_id');
  String get organizationId => str('organization_id');
  String get mode => str('mode');
  String get state => str('state');
  String get expiresAt => str('expires_at');
}

final class EffectivePermissions extends ApiObject {
  EffectivePermissions(super.data);
  List<String> get permissions => strings('permissions');
  Map<String, List<String>> get provenance {
    final v = data['provenance'];
    if (v is! Map<String, Object?>) return const {};
    return Map.unmodifiable({
      for (final e in v.entries)
        e.key: e.value is List<Object?>
            ? List<String>.unmodifiable(
                (e.value! as List<Object?>).whereType<String>())
            : const <String>[],
    });
  }

  List<Map<String, Object?>> get sources {
    final v = data['sources'];
    return v is List<Object?>
        ? List.unmodifiable(v.whereType<Map<String, Object?>>())
        : const [];
  }

  int get restrictingPolicies => integer('restricting_policies');
}

/// What [AdminClient.setUserState] does.
enum UserStateAction { suspend, reactivate, lock }

/// A subject or scope reference for role assignments.
final class Ref {
  const Ref(this.type, this.id);
  final String type;
  final String id;
  Map<String, String> toJson() => {'type': type, 'id': id};
}

final Random _random = Random.secure();

/// A random idempotency key (128 bits, hex).
String newIdempotencyKey() =>
    List<int>.generate(16, (_) => _random.nextInt(256))
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();

String _seg(String v) {
  if (v.isEmpty) {
    throw ArgumentError('admin: path identifiers must be non-empty strings');
  }
  return Uri.encodeComponent(v);
}

String _stripQuery(String path) {
  final q = path.indexOf('?');
  return q >= 0 ? path.substring(0, q) : path;
}

String _query(Map<String, String> params) => Uri(queryParameters: params).query;

/// Calls one realm's custom APIs under `/api/v1/realms/{realm}`.
final class AdminClient {
  /// Creates a client. Throws [ArgumentError] for an invalid configuration.
  ///
  /// - [baseUrl]: e.g. `https://id.example.com`.
  /// - [token] or [tokenSource]: a static bearer token, or a function called
  ///   once per request (not both).
  /// - [timeout]: default request deadline (30 s).
  /// - [userAgent]: sent before `proudauth-sdk-dart/<version>`.
  /// - [maxResponseBytes]: maximum response size (default 32 MiB).
  /// - [onDeprecated]: called for responses of operations the server marks
  ///   deprecated (Deprecation and Sunset headers, API-013), also for error
  ///   responses; the path has no query string.
  factory AdminClient({
    required String baseUrl,
    required String realm,
    String? token,
    TokenSource? tokenSource,
    Duration timeout = const Duration(seconds: 30),
    String? userAgent,
    http.Client? httpClient,
    int maxResponseBytes = 32 << 20,
    void Function(DeprecationNotice notice)? onDeprecated,
  }) {
    if (realm.isEmpty) throw ArgumentError('admin: realm is required');
    final base = requireHttpUrl(baseUrl, 'baseUrl', 'admin');
    if (token != null && tokenSource != null) {
      throw ArgumentError('admin: pass either token or tokenSource, not both');
    }
    if (timeout <= Duration.zero) {
      throw ArgumentError('admin: timeout must be positive');
    }
    if (maxResponseBytes <= 0) {
      throw ArgumentError('admin: maxResponseBytes must be positive');
    }
    return AdminClient._(
      '${trimTrailingSlashes(base.toString())}/api/v1/realms/${Uri.encodeComponent(realm)}',
      token != null ? (_) => token : tokenSource,
      timeout,
      userAgent,
      httpClient ?? http.Client(),
      httpClient == null,
      maxResponseBytes,
      onDeprecated,
    );
  }

  AdminClient._(this._base, this._token, this._timeout, this._userAgent,
      this._client, this._ownsClient, this._maxBytes, this._onDeprecated);

  final String _base;
  final TokenSource? _token;
  final Duration _timeout;
  final String? _userAgent;
  final http.Client _client;
  final bool _ownsClient;
  final int _maxBytes;
  final void Function(DeprecationNotice notice)? _onDeprecated;

  /// Closes the HTTP client the admin client created (not one passed in).
  void close() {
    if (_ownsClient) _client.close();
  }

  /// Performs a request against `/api/v1/realms/{realm}{path}` and decodes
  /// JSON. [body] (when not null) is sent as JSON. Throws
  /// [ProblemException] for HTTP errors and [AdminRequestException] for
  /// transport failures, timeouts and cancellation.
  Future<AdminResponse<Object?>> request(
    String method,
    String path, {
    Object? body,
    RequestOptions options = const RequestOptions(),
  }) async {
    if (!path.startsWith('/')) {
      throw ArgumentError('admin: path must start with "/"');
    }
    final plain = _stripQuery(path);
    final deadline = CancelToken.timeout(options.timeout ?? _timeout);
    final callerToken = options.cancelToken;
    final combined = callerToken == null
        ? deadline
        : CancelToken.any([deadline, callerToken]);
    AdminRequestException fail(Object cause) {
      final code = callerToken != null && callerToken.isCancelled
          ? AdminErrorCode.aborted
          : deadline.isCancelled || cause is HttpTimeoutException
              ? AdminErrorCode.timeout
              : AdminErrorCode.network;
      return AdminRequestException(code, method, plain, cause: cause);
    }

    try {
      final headers = <String, String>{
        'accept': 'application/json, application/problem+json',
        if (body != null) 'content-type': 'application/json',
        'proudauth-sdk': 'dart/$sdkVersion',
        'user-agent':
            '${_userAgent != null && _userAgent.isNotEmpty ? '$_userAgent ' : ''}proudauth-sdk-dart/$sdkVersion',
      };
      final source = _token;
      if (source != null) {
        final String tok;
        try {
          tok = await source(combined);
        } catch (cause) {
          throw AdminRequestException(AdminErrorCode.tokenSource, method, plain,
              cause: cause);
        }
        headers['authorization'] = 'Bearer $tok';
      }
      final key = options.idempotencyKey;
      if (key != null && key.isNotEmpty) headers['idempotency-key'] = key;
      final ifMatch = options.ifMatch;
      if (ifMatch != null && ifMatch.isNotEmpty) headers['if-match'] = ifMatch;

      final HttpResult res;
      try {
        res = await sendRequest(
          _client,
          method: method,
          url: Uri.parse(_base + path),
          headers: headers,
          body: body == null ? null : utf8.encode(jsonEncode(body)),
          // The deadline token enforces the overall timeout.
          timeout: (options.timeout ?? _timeout) + const Duration(seconds: 1),
          cancelToken: combined,
          maxBodyBytes: _maxBytes,
        );
      } catch (cause) {
        throw fail(cause);
      }
      if (res.status >= 300 && res.status < 400) {
        // Redirects are never followed (credentials stay with this origin).
        throw fail(StateError('redirect refused (HTTP ${res.status})'));
      }
      Object? parsed;
      if (res.body.isNotEmpty) {
        try {
          parsed = jsonDecode(decodeUtf8Lenient(res.body));
        } on FormatException catch (cause) {
          if (res.status < 400) {
            throw AdminRequestException(
                AdminErrorCode.invalidResponse, method, plain,
                cause: cause);
          }
          parsed = null;
        }
      }
      final deprecation = res.headers['deprecation'];
      final sunset = res.headers['sunset'];
      final onDeprecated = _onDeprecated;
      if (deprecation != null &&
          deprecation.isNotEmpty &&
          onDeprecated != null) {
        onDeprecated(DeprecationNotice(method, plain, deprecation, sunset));
      }
      if (res.status >= 400) {
        throw ProblemException(
          res.status,
          parsed is Map<String, Object?> ? parsed : const {},
          res.headers,
        );
      }
      return AdminResponse<Object?>(
        status: res.status,
        headers: res.headers,
        etag: res.headers['etag'],
        deprecation: deprecation,
        sunset: sunset,
        data: wrapSecrets(parsed),
      );
    } finally {
      deadline.cancel();
      if (!identical(combined, deadline)) combined.cancel();
    }
  }

  Future<AdminResponse<T>> _typed<T>(
    String method,
    String path,
    T Function(Map<String, Object?> json) decode, {
    Object? body,
    RequestOptions options = const RequestOptions(),
  }) async {
    final res = await request(method, path, body: body, options: options);
    final data = res.data;
    return AdminResponse<T>(
      status: res.status,
      headers: res.headers,
      etag: res.etag,
      deprecation: res.deprecation,
      sunset: res.sunset,
      data: decode(data is Map<String, Object?> ? data : const {}),
    );
  }

  Future<Map<String, Object?>> _object(
    String method,
    String path, {
    Object? body,
    RequestOptions options = const RequestOptions(),
  }) async {
    final res = await request(method, path, body: body, options: options);
    final data = res.data;
    return data is Map<String, Object?> ? data : <String, Object?>{};
  }

  /// Iterates the pages of a cursor-paginated list endpoint (API-004).
  /// [decode] converts each item; a repeated cursor stops with
  /// `invalid_response` instead of looping.
  Stream<Page<T>> pages<T>(
    String path,
    T Function(Object? item) decode, {
    RequestOptions options = const RequestOptions(),
  }) async* {
    var cursor = '';
    final seen = <String>{};
    for (;;) {
      var p = path;
      if (cursor.isNotEmpty) {
        p +=
            '${p.contains('?') ? '&' : '?'}cursor=${Uri.encodeComponent(cursor)}';
      }
      final res = await request('GET', p, options: options);
      final data = res.data;
      final items =
          data is Map<String, Object?> && data['items'] is List<Object?>
              ? (data['items']! as List<Object?>).map(decode).toList()
              : <T>[];
      final next = data is Map<String, Object?> && data['next_cursor'] is String
          ? data['next_cursor']! as String
          : '';
      yield Page<T>(items, next);
      if (next.isEmpty) return;
      if (!seen.add(next)) {
        // cursor loop
        throw AdminRequestException(
            AdminErrorCode.invalidResponse, 'GET', _stripQuery(path));
      }
      cursor = next;
    }
  }

  /// Iterates every item of a cursor-paginated list endpoint.
  Stream<T> list<T>(
    String path,
    T Function(Object? item) decode, {
    RequestOptions options = const RequestOptions(),
  }) async* {
    await for (final page in pages(path, decode, options: options)) {
      yield* Stream.fromIterable(page.items);
    }
  }

  static Map<String, Object?> _map(Object? v) =>
      v is Map<String, Object?> ? v : const {};

  Future<List<T>> _items<T>(
    String path,
    T Function(Map<String, Object?> json) decode,
    RequestOptions options, {
    String member = 'items',
  }) async {
    final res = await request('GET', path, options: options);
    final data = res.data;
    if (data is Map<String, Object?> && data[member] is List<Object?>) {
      return (data[member]! as List<Object?>)
          .map((e) => decode(_map(e)))
          .toList();
    }
    return <T>[];
  }

  RequestOptions _idempotent(RequestOptions o) {
    final k = o.idempotencyKey;
    return k != null && k.isNotEmpty ? o : o._withKey(newIdempotencyKey());
  }

  /// Lists users matching [query].
  Stream<User> users(
          [String query = '',
          RequestOptions options = const RequestOptions()]) =>
      list('/users?${_query({'q': query})}', (e) => User(_map(e)),
          options: options);

  /// Reads a user with its ETag.
  Future<AdminResponse<User>> getUser(String userId,
          [RequestOptions options = const RequestOptions()]) async =>
      _typed('GET', '/users/${_seg(userId)}', User.new, options: options);

  /// Creates a user. A random idempotency key is used unless one is given
  /// (reuse it when retrying).
  Future<Map<String, Object?>> createUser(Map<String, Object?> input,
          [RequestOptions options = const RequestOptions()]) =>
      _object('POST', '/users', body: input, options: _idempotent(options));

  /// Updates a user; pass the ETag from [getUser] as `ifMatch` to reject
  /// stale writes.
  Future<AdminResponse<User>> updateUser(
          String userId, Map<String, Object?> patch,
          [RequestOptions options = const RequestOptions()]) async =>
      _typed('PATCH', '/users/${_seg(userId)}', User.new,
          body: patch, options: options);

  /// Suspends, reactivates or locks a user.
  Future<void> setUserState(
      String userId, UserStateAction action, String reason,
      [RequestOptions options = const RequestOptions()]) async {
    await request('POST', '/users/${_seg(userId)}/${action.name}',
        body: {'reason': reason}, options: options);
  }

  /// Revokes all sessions of a user; returns the number revoked.
  Future<int> revokeSessions(String userId,
      [RequestOptions options = const RequestOptions()]) async {
    final data = await _object('POST', '/users/${_seg(userId)}/revoke-sessions',
        body: const <String, Object?>{}, options: options);
    final n = data['revoked_sessions'];
    return n is num ? n.toInt() : 0;
  }

  /// Lists organizations.
  Stream<Organization> organizations(
          [RequestOptions options = const RequestOptions()]) =>
      list('/organizations', (e) => Organization(_map(e)), options: options);

  /// Creates an organization.
  Future<Organization> createOrganization(String slug, String displayName,
          [RequestOptions options = const RequestOptions()]) async =>
      Organization(await _object('POST', '/organizations',
          body: {'slug': slug, 'display_name': displayName},
          options: _idempotent(options)));

  /// Lists organization members.
  Stream<Membership> members(String orgId,
      [RequestOptions options = const RequestOptions()]) async* {
    yield* list(
        '/organizations/${_seg(orgId)}/members', (e) => Membership(_map(e)),
        options: options);
  }

  /// Adds an existing user to an organization.
  Future<Membership> addMember(
          String orgId, String userId, List<String> roleIds,
          [RequestOptions options = const RequestOptions()]) async =>
      Membership(await _object('POST', '/organizations/${_seg(orgId)}/members',
          body: {'user_id': userId, 'role_ids': roleIds}, options: options));

  /// Creates an invitation.
  Future<Map<String, Object?>> invite(
          String orgId, String email, List<String> roleIds,
          [RequestOptions options = const RequestOptions()]) async =>
      _object('POST', '/organizations/${_seg(orgId)}/invitations',
          body: {'email': email, 'role_ids': roleIds},
          options: _idempotent(options));

  /// Lists roles for a boundary type.
  Future<List<Role>> roles(String boundary,
          [RequestOptions options = const RequestOptions()]) =>
      _items(
          '/roles?${_query({'boundary_type': boundary})}', Role.new, options);

  /// Assigns a role to a subject within a scope.
  Future<Map<String, Object?>> assign(String roleId, Ref subject, Ref scope,
          [RequestOptions options = const RequestOptions()]) =>
      _object('POST', '/role-assignments',
          body: {
            'role_id': roleId,
            'subject': subject.toJson(),
            'scope': scope.toJson(),
          },
          options: options);

  /// Registers an OAuth client; the secret is returned once (as a
  /// [Secret]).
  Future<Map<String, Object?>> createClient(Map<String, Object?> input,
          [RequestOptions options = const RequestOptions()]) =>
      _object('POST', '/clients', body: input, options: options);

  /// Issues an overlapping client secret.
  Future<Map<String, Object?>> rotateClientSecret(
          String clientRef, Duration retireOthersAfter,
          [RequestOptions options = const RequestOptions()]) async =>
      _object('POST', '/clients/${_seg(clientRef)}/credentials',
          body: {'retire_others_after_seconds': retireOthersAfter.inSeconds},
          options: options);

  /// Requests support access (requires recent MFA and a reason).
  Future<Map<String, Object?>> requestImpersonation(Map<String, Object?> input,
          [RequestOptions options = const RequestOptions()]) =>
      _object('POST', '/impersonation-requests', body: input, options: options);

  /// Issues an approved support grant.
  Future<Map<String, Object?>> issueImpersonation(String requestId,
          [RequestOptions options = const RequestOptions()]) async =>
      _object('POST', '/impersonation-requests/${_seg(requestId)}/issue',
          options: options);

  /// Ends a support grant.
  Future<void> revokeImpersonation(String grantId, String reason,
      [RequestOptions options = const RequestOptions()]) async {
    await request('POST', '/impersonation-grants/${_seg(grantId)}/revoke',
        body: {'reason': reason}, options: options);
  }

  /// Lists OAuth clients.
  Stream<OAuthClientSummary> clients(
          [RequestOptions options = const RequestOptions()]) =>
      list('/clients', (e) => OAuthClientSummary(_map(e)), options: options);

  /// Sets the scopes and subject types a client may request for a resource.
  Future<void> setResourceGrant(String clientRef, String resourceId,
      List<String> scopes, List<String> subjectTypes,
      [RequestOptions options = const RequestOptions()]) async {
    await request('PUT',
        '/clients/${_seg(clientRef)}/resource-grants/${_seg(resourceId)}',
        body: {'allowed_scopes': scopes, 'subject_types': subjectTypes},
        options: options);
  }

  /// Lists a user's active sessions.
  Future<List<SessionSummary>> userSessions(String userId,
          [RequestOptions options = const RequestOptions()]) async =>
      _items('/users/${_seg(userId)}/sessions', SessionSummary.new, options);

  /// Revokes one session of a user (SES-003).
  Future<void> revokeSession(String userId, String sessionId,
      [RequestOptions options = const RequestOptions()]) async {
    await request(
        'DELETE', '/users/${_seg(userId)}/sessions/${_seg(sessionId)}',
        options: options);
  }

  /// Lists an organization's invitations, optionally by state.
  Stream<InvitationSummary> invitations(String orgId,
      {String state = '',
      RequestOptions options = const RequestOptions()}) async* {
    yield* list(
        '/organizations/${_seg(orgId)}/invitations?${_query({'state': state})}',
        (e) => InvitationSummary(_map(e)),
        options: options);
  }

  /// Revokes a pending invitation.
  Future<void> revokeInvitation(String orgId, String invitationId,
      [RequestOptions options = const RequestOptions()]) async {
    await request('POST',
        '/organizations/${_seg(orgId)}/invitations/${_seg(invitationId)}/revoke',
        options: options);
  }

  /// Creates up to 100 invitations with per-item results (INV-011). A random
  /// idempotency key is used unless one is given.
  Future<List<Map<String, Object?>>> inviteBatch(
      String orgId, List<Map<String, Object?>> items,
      [RequestOptions options = const RequestOptions()]) async {
    final data = await _object(
        'POST', '/organizations/${_seg(orgId)}/invitations/batch',
        body: {'items': items}, options: _idempotent(options));
    final results = data['results'];
    return results is List<Object?>
        ? results.map(_map).toList()
        : <Map<String, Object?>>[];
  }

  /// Lists support grants (filters: actor_user_id, target_user_id,
  /// organization_id, state).
  Future<List<SupportGrant>> impersonationGrants(
          [Map<String, String> filter = const {},
          RequestOptions options = const RequestOptions()]) =>
      _items(
          '/impersonation-grants?${_query(filter)}', SupportGrant.new, options);

  /// Explains a subject's effective permissions with provenance (AZ-009).
  Future<EffectivePermissions> subjectPermissions(String subjectId,
      {String orgId = '',
      RequestOptions options = const RequestOptions()}) async {
    final q = orgId.isEmpty ? '' : '?${_query({'organization_id': orgId})}';
    return EffectivePermissions(await _object(
        'GET', '/subjects/${_seg(subjectId)}/permissions$q',
        options: options));
  }

  /// Queries audit evidence.
  Stream<Map<String, Object?>> auditEvents(
          [Map<String, String> filter = const {},
          RequestOptions options = const RequestOptions()]) =>
      list('/audit-events?${_query(filter)}', _map, options: options);
}
