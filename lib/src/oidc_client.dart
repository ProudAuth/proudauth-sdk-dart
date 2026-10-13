/// Confidential-client helper for backends-for-frontends (SDK-004), a port
/// of the Node.js SDK's `oidc-client.ts`: authorization code + PKCE S256,
/// state and nonce handling, RFC 9207 issuer checks, strict ID-token
/// validation (OIDC-016), server-side token storage with single-flight
/// refresh (SES-009), revocation and RP-initiated logout.
///
/// The issuer is trusted configuration. Discovery is fetched only from it,
/// every advertised endpoint must share the issuer's origin, and keys are
/// resolved only from the advertised jwks_uri (never from a token header).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256, sha512;
import 'package:http/http.dart' as http;

import 'cancel.dart';
import 'claims.dart' show dateFromSeconds;
import 'internal/base64url.dart';
import 'internal/crypto/bigint.dart' show constantTimeEquals;
import 'internal/http.dart';
import 'internal/json.dart';
import 'internal/jwks.dart';
import 'internal/jws.dart';

/// OIDC client error categories.
enum OidcErrorCode {
  state('state', 'state mismatch'),
  idToken('id_token', 'invalid ID token'),
  nonce('nonce', 'nonce mismatch'),
  reauthenticate(
      'reauthenticate', 'refresh failed; the user must authenticate again'),
  provider('provider', 'provider error'),
  configuration('configuration', 'invalid configuration');

  const OidcErrorCode(this.value, this.description);

  /// The category string of the Node.js SDK (`OIDCError.code`).
  final String value;
  final String description;
}

/// OIDC client failures (the Node.js SDK's `OIDCError`). Messages carry
/// categories only, never tokens, codes or secrets.
final class OidcException implements Exception {
  OidcException(this.code,
      {this.reason, this.providerError, this.status, this.cause});

  final OidcErrorCode code;

  /// The failed check (e.g. "issuer", "audience", "at_hash") or provider
  /// detail.
  final String? reason;

  /// OAuth error code returned by the provider, when there is one.
  final String? providerError;

  /// HTTP status from the provider, when there is one.
  final int? status;

  final Object? cause;

  String get message {
    final extra = [
      if (reason != null && reason!.isNotEmpty) reason!,
      if (providerError != null && providerError!.isNotEmpty) providerError!,
      if (status != null) 'HTTP $status',
    ].join(', ');
    return 'oidc-client: ${code.description}${extra.isEmpty ? '' : ' ($extra)'}';
  }

  @override
  String toString() => message;
}

final Random _random = Random.secure();

/// A URL-safe random value with 256 bits of entropy (state, nonce, PKCE
/// verifier).
String randomValue() => encodeBase64Url(
    Uint8List.fromList(List<int>.generate(32, (_) => _random.nextInt(256))));

/// The S256 PKCE challenge for a verifier (RFC 7636).
String pkceChallenge(String verifier) => encodeBase64Url(
    sha256.convert(verifier.codeUnits.map((c) => c & 0xff).toList()).bytes);

/// at_hash / c_hash: left half of the hash matching the signing algorithm
/// (OIDC Core §3.1.3.6).
String halfHash(String alg, String value) {
  final d =
      (alg == 'EdDSA' ? sha512 : sha256).convert(utf8.encode(value)).bytes;
  return encodeBase64Url(d.sublist(0, d.length ~/ 2));
}

/// The per-login state. Store it server-side (e.g. keyed by a random value
/// in an HttpOnly cookie), never only in a client-readable cookie, and use
/// it once.
final class AuthRequest {
  AuthRequest({
    required this.state,
    required this.nonce,
    required this.codeVerifier,
    required this.url,
    required this.redirectUri,
    required List<String> scopes,
    required this.createdAt,
  }) : scopes = List.unmodifiable(scopes);

  /// Restores a request stored with [toJson].
  factory AuthRequest.fromJson(Map<String, Object?> json) => AuthRequest(
        state: json['state']! as String,
        nonce: json['nonce']! as String,
        codeVerifier: json['code_verifier']! as String,
        url: json['url']! as String,
        redirectUri: json['redirect_uri']! as String,
        scopes: (json['scopes']! as List<Object?>).cast<String>(),
        createdAt: DateTime.parse(json['created_at']! as String),
      );

  final String state;
  final String nonce;
  final String codeVerifier;

  /// Where to send the browser.
  final String url;
  final String redirectUri;
  final List<String> scopes;
  final DateTime createdAt;

  /// For server-side storage only (it holds the PKCE verifier).
  Map<String, Object?> toJson() => {
        'state': state,
        'nonce': nonce,
        'code_verifier': codeVerifier,
        'url': url,
        'redirect_uri': redirectUri,
        'scopes': scopes,
        'created_at': createdAt.toUtc().toIso8601String(),
      };

  @override
  String toString() => 'AuthRequest(url: $url)';
}

/// Tokens returned by the token endpoint.
final class TokenSet {
  const TokenSet({
    required this.accessToken,
    required this.tokenType,
    required this.expiresIn,
    this.refreshToken,
    this.idToken,
    this.scope,
    required this.expiresAt,
  });

  /// Restores tokens stored with [toJson].
  factory TokenSet.fromJson(Map<String, Object?> json) => TokenSet(
        accessToken: json['access_token']! as String,
        tokenType: json['token_type']! as String,
        expiresIn: json['expires_in']! as num,
        refreshToken: json['refresh_token'] as String?,
        idToken: json['id_token'] as String?,
        scope: json['scope'] as String?,
        expiresAt: DateTime.parse(json['expires_at']! as String),
      );

  final String accessToken;
  final String tokenType;
  final num expiresIn;
  final String? refreshToken;
  final String? idToken;
  final String? scope;

  /// Absolute access-token expiry.
  final DateTime expiresAt;

  TokenSet _merge(TokenSet previous) => TokenSet(
        accessToken: accessToken,
        tokenType: tokenType,
        expiresIn: expiresIn,
        refreshToken: refreshToken ?? previous.refreshToken,
        idToken: idToken ?? previous.idToken,
        scope: scope,
        expiresAt: expiresAt,
      );

  /// For server-side persistence only: the result holds the tokens.
  Map<String, Object?> toJson() => {
        'access_token': accessToken,
        'token_type': tokenType,
        'expires_in': expiresIn,
        if (refreshToken != null) 'refresh_token': refreshToken,
        if (idToken != null) 'id_token': idToken,
        if (scope != null) 'scope': scope,
        'expires_at': expiresAt.toUtc().toIso8601String(),
      };

  /// Never prints token values.
  @override
  String toString() => 'TokenSet(expiresAt: $expiresAt, scope: $scope)';
}

/// The verified claims of an ID token.
final class IdTokenClaims {
  IdTokenClaims._({
    required this.issuer,
    required this.subject,
    required this.audience,
    required this.expiry,
    required this.issuedAt,
    required this.authTime,
    required this.nonce,
    required this.acr,
    required this.amr,
    required this.azp,
    required this.sid,
    required this.atHash,
    required this.email,
    required this.name,
    required this.claims,
  });

  final String issuer;
  final String subject;
  final List<String> audience;
  final DateTime expiry;
  final DateTime? issuedAt;
  final DateTime? authTime;
  final String? nonce;
  final String? acr;
  final List<String> amr;
  final String? azp;
  final String? sid;
  final String? atHash;
  final String? email;
  final String? name;

  /// Every verified claim, for application-specific fields.
  final Map<String, Object?> claims;
}

/// `token_type_hint` for revocation (RFC 7009).
enum TokenTypeHint {
  refreshToken('refresh_token'),
  accessToken('access_token');

  const TokenTypeHint(this.value);
  final String value;
}

const Set<String> _reservedAuthParams = {
  'client_id',
  'redirect_uri',
  'response_type',
  'state',
  'nonce',
  'code_challenge',
  'code_challenge_method',
  'scope',
  'resource',
  'request',
  'request_uri',
};

/// Provider responses larger than this are refused (1 MiB).
const int _maxProviderResponseBytes = 1 << 20;

/// The backend-for-frontend OIDC client.
final class OidcClient {
  /// Creates a client. Throws [ArgumentError] for an invalid configuration.
  ///
  /// - [clientSecret]: omit (or pass an empty string) for public clients;
  ///   `client_id` is then sent in the request body.
  /// - [scopes]: default `["openid"]`.
  /// - [resource]: RFC 8707 resource indicator requested by default.
  /// - [algorithms]: ID-token algorithm allowlist; default RS256, PS256,
  ///   ES256, EdDSA.
  /// - [clockSkew]: ID-token clock tolerance (default 30 s, at most 60 s).
  /// - [timeout]: provider request timeout (default 10 s).
  /// - [jwksMinRefreshInterval]: minimum spacing of JWKS refreshes for
  ///   unknown key IDs (default 30 s, at least 1 s).
  factory OidcClient({
    required String issuer,
    required String clientId,
    String? clientSecret,
    required String redirectUri,
    List<String>? scopes,
    String? resource,
    List<String>? algorithms,
    Duration clockSkew = const Duration(seconds: 30),
    Duration timeout = const Duration(seconds: 10),
    Duration jwksMinRefreshInterval = const Duration(seconds: 30),
    http.Client? httpClient,
    DateTime Function()? now,
  }) {
    const prefix = 'oidc-client';
    if (issuer.isEmpty || clientId.isEmpty || redirectUri.isEmpty) {
      throw ArgumentError(
          'oidc-client: issuer, client ID and redirect URI are required');
    }
    final issuerUri = requireHttpUrl(issuer, 'issuer', prefix);
    requireHttpUrl(redirectUri, 'redirectUri', prefix);
    final algs = resolveAlgorithms(algorithms, prefix);
    if (clockSkew.isNegative || clockSkew > const Duration(seconds: 60)) {
      throw ArgumentError('oidc-client: clock skew must be between 0 and 60s');
    }
    if (timeout <= Duration.zero) {
      throw ArgumentError('oidc-client: timeout must be positive');
    }
    if (jwksMinRefreshInterval < const Duration(seconds: 1)) {
      throw ArgumentError(
          'oidc-client: jwksMinRefreshInterval must be at least 1s');
    }
    return OidcClient._(
      issuer: issuer,
      issuerOrigin: originOf(issuerUri),
      clientId: clientId,
      clientSecret:
          clientSecret == null || clientSecret.isEmpty ? null : clientSecret,
      redirectUri: redirectUri,
      scopes: List.unmodifiable(
          scopes == null || scopes.isEmpty ? const ['openid'] : scopes),
      resource: resource == null || resource.isEmpty ? null : resource,
      algorithms: algs,
      skew: clockSkew,
      timeout: timeout,
      minRefresh: jwksMinRefreshInterval,
      client: httpClient ?? http.Client(),
      ownsClient: httpClient == null,
      now: now ?? DateTime.now,
    );
  }

  OidcClient._({
    required String issuer,
    required String issuerOrigin,
    required String clientId,
    required String? clientSecret,
    required String redirectUri,
    required List<String> scopes,
    required String? resource,
    required Set<String> algorithms,
    required Duration skew,
    required Duration timeout,
    required Duration minRefresh,
    required http.Client client,
    required bool ownsClient,
    required DateTime Function() now,
  })  : _issuer = issuer,
        _issuerOrigin = issuerOrigin,
        _clientId = clientId,
        _clientSecret = clientSecret,
        _redirectUri = redirectUri,
        _scopes = scopes,
        _resource = resource,
        _algorithms = algorithms,
        _skew = skew,
        _timeout = timeout,
        _minRefresh = minRefresh,
        _client = client,
        _ownsClient = ownsClient,
        _now = now;

  final String _issuer;
  final String _issuerOrigin;
  final String _clientId;
  final String? _clientSecret;
  final String _redirectUri;
  final List<String> _scopes;
  final String? _resource;
  final Set<String> _algorithms;
  final Duration _skew;
  final Duration _timeout;
  final Duration _minRefresh;
  final http.Client _client;
  final bool _ownsClient;
  final DateTime Function() _now;
  Future<Map<String, Object?>>? _meta;
  JwksCache? _jwks;

  String get issuer => _issuer;

  String get clientId => _clientId;

  /// JWKS fetches made for ID-token validation (diagnostics and tests).
  int get jwksFetchCount => _jwks?.fetchCount ?? 0;

  /// Closes the HTTP client the OIDC client created (not one passed in).
  void close() {
    if (_ownsClient) _client.close();
  }

  /// Loads (once) and returns the issuer's discovery document. A failed load
  /// is retried on the next call.
  Future<Map<String, Object?>> discover({CancelToken? cancelToken}) {
    var meta = _meta;
    if (meta == null) {
      final p = _loadDiscovery();
      _meta = meta = p;
      p.then<void>((_) {}, onError: (Object _) {
        if (identical(_meta, p)) _meta = null; // retry on the next call
      });
    }
    return waitFor(meta, cancelToken,
        () => OidcException(OidcErrorCode.provider, reason: 'aborted'));
  }

  Future<Map<String, Object?>> _loadDiscovery() async {
    final url =
        '${trimTrailingSlashes(_issuer)}/.well-known/openid-configuration';
    final m = await _getJson(Uri.parse(url));
    if (m['issuer'] != _issuer) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'discovery issuer mismatch');
    }
    return Map.unmodifiable(m);
  }

  Future<Map<String, Object?>> _getJson(Uri url) async {
    final HttpResult res;
    try {
      res = await sendRequest(
        _client,
        method: 'GET',
        url: url,
        headers: const {'accept': 'application/json'},
        timeout: _timeout,
        maxBodyBytes: _maxProviderResponseBytes,
        readBody: (status) => status == 200,
      );
    } on BodyTooLargeException catch (cause) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'invalid metadata', cause: cause);
    } catch (cause) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'unreachable', cause: cause);
    }
    if (res.status != 200) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'metadata request failed', status: res.status);
    }
    try {
      final v = parseStrictJsonBytes(res.body);
      if (v is! Map<String, Object?>) {
        throw const FormatException('not an object');
      }
      return v;
    } catch (cause) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'invalid metadata', cause: cause);
    }
  }

  Future<Uri> _endpoint(String name, CancelToken? cancelToken) async {
    final m = await discover(cancelToken: cancelToken);
    final s = m[name];
    if (s is! String || s.isEmpty) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'missing endpoint $name');
    }
    final u = Uri.tryParse(s);
    if (u == null ||
        !u.hasScheme ||
        (u.scheme != 'https' && u.scheme != 'http') ||
        u.host.isEmpty) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'invalid endpoint $name');
    }
    // Endpoints must live on the trusted issuer's origin.
    if (originOf(u) != _issuerOrigin || u.userInfo.isNotEmpty) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'endpoint $name is not on the issuer origin');
    }
    return u;
  }

  /// Builds an authorization request with state, nonce, PKCE S256 and the
  /// resource indicator. [extraParams] cannot override security parameters
  /// ([ArgumentError]).
  Future<AuthRequest> authorizationUrl({
    Map<String, String> extraParams = const {},
    List<String>? scopes,
    String? resource,
    CancelToken? cancelToken,
  }) async {
    final ep = await _endpoint('authorization_endpoint', cancelToken);
    final s = scopes == null || scopes.isEmpty ? _scopes : scopes;
    final state = randomValue();
    final nonce = randomValue();
    final codeVerifier = randomValue();
    final q = <String, List<String>>{
      for (final e in ep.queryParametersAll.entries) e.key: [...e.value],
    };
    void set(String k, String v) => q[k] = [v];
    set('client_id', _clientId);
    set('redirect_uri', _redirectUri);
    set('response_type', 'code');
    set('scope', s.join(' '));
    set('state', state);
    set('nonce', nonce);
    set('code_challenge', pkceChallenge(codeVerifier));
    set('code_challenge_method', 'S256');
    final r = resource ?? _resource;
    if (r != null && r.isNotEmpty) set('resource', r);
    for (final e in extraParams.entries) {
      // Security parameters cannot be overridden through extra parameters.
      if (_reservedAuthParams.contains(e.key)) {
        throw ArgumentError(
            'oidc-client: ${e.key} cannot be set through extraParams');
      }
      set(e.key, e.value);
    }
    return AuthRequest(
      state: state,
      nonce: nonce,
      codeVerifier: codeVerifier,
      url: ep.replace(queryParameters: q).toString(),
      redirectUri: _redirectUri,
      scopes: s,
      createdAt: _now(),
    );
  }

  /// Validates the callback (state, RFC 9207 issuer), redeems the code with
  /// the PKCE verifier and validates the ID token (nonce, at_hash) before
  /// returning tokens.
  ///
  /// [callback] is the callback [Uri], the callback URL or its query string
  /// as a [String], or its parameters as a `Map<String, String>` or
  /// `Map<String, List<String>>`.
  Future<({TokenSet tokens, IdTokenClaims? idClaims})> exchangeCode(
    AuthRequest authRequest,
    Object callback, {
    CancelToken? cancelToken,
  }) async {
    final params = _toParams(callback);
    String? one(String k) {
      final all = params[k];
      if (all == null || all.isEmpty) return null;
      if (all.length > 1) {
        throw OidcException(OidcErrorCode.provider,
            reason: 'duplicate $k parameter');
      }
      return all.first;
    }

    final error = one('error');
    final state = one('state');
    if (state == null ||
        state.isEmpty ||
        !_safeEqual(state, authRequest.state)) {
      throw OidcException(OidcErrorCode.state);
    }
    final meta = await discover(cancelToken: cancelToken);
    final iss = one('iss');
    if (iss != null && iss != _issuer) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'authorization response issuer mismatch (mix-up)');
    }
    if (iss == null &&
        meta['authorization_response_iss_parameter_supported'] == true) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'authorization response is missing iss');
    }
    if (error != null) {
      throw OidcException(OidcErrorCode.provider,
          providerError: _safeCode(error));
    }
    final code = one('code');
    if (code == null || code.isEmpty) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'missing authorization code');
    }

    final tokens = await _tokenRequest({
      'grant_type': 'authorization_code',
      'code': code,
      'code_verifier': authRequest.codeVerifier,
      'redirect_uri': authRequest.redirectUri,
    }, cancelToken);
    IdTokenClaims? idClaims;
    final idToken = tokens.idToken;
    if (idToken != null) {
      idClaims = await validateIdToken(
        idToken,
        nonce: authRequest.nonce,
        accessToken: tokens.accessToken,
        cancelToken: cancelToken,
      );
    } else if (authRequest.scopes.contains('openid')) {
      throw OidcException(OidcErrorCode.idToken, reason: 'missing ID token');
    }
    return (tokens: tokens, idClaims: idClaims);
  }

  Future<TokenSet> _tokenRequest(
      Map<String, String> fields, CancelToken? cancelToken) async {
    final ep = await _endpoint('token_endpoint', cancelToken);
    final headers = <String, String>{
      'content-type': 'application/x-www-form-urlencoded',
      'accept': 'application/json',
    };
    final form = <String, String>{...fields};
    final secret = _clientSecret;
    if (secret != null) {
      headers['authorization'] = basicAuthorization(_clientId, secret);
    } else {
      form['client_id'] = _clientId;
    }
    final HttpResult res;
    try {
      res = await sendRequest(
        _client,
        method: 'POST',
        url: ep,
        headers: headers,
        body: utf8.encode(formBody(form)),
        timeout: _timeout,
        cancelToken: cancelToken,
        maxBodyBytes: _maxProviderResponseBytes,
      );
    } on BodyTooLargeException catch (cause) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'invalid token response', cause: cause);
    } catch (cause) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'token endpoint unreachable', cause: cause);
    }
    Object? body;
    try {
      body = parseStrictJsonBytes(res.body);
    } catch (cause) {
      body = null;
      if (res.status == 200) {
        throw OidcException(OidcErrorCode.provider,
            reason: 'invalid token response', status: 200, cause: cause);
      }
    }
    if (res.status != 200) {
      final err = body is Map<String, Object?> && body['error'] is String
          ? body['error']! as String
          : null;
      if (err == 'invalid_grant') {
        throw OidcException(OidcErrorCode.reauthenticate,
            providerError: err, status: res.status);
      }
      throw OidcException(OidcErrorCode.provider,
          reason: 'token endpoint error',
          providerError: err == null ? null : _safeCode(err),
          status: res.status);
    }
    if (body is! Map<String, Object?>) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'invalid token response');
    }
    final at = body['access_token'];
    final tt = body['token_type'];
    final ei = body['expires_in'];
    final rt = body['refresh_token'];
    final it = body['id_token'];
    final scope = body['scope'];
    if (at is! String || at.isEmpty) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'missing access_token');
    }
    if (tt is! String || tt.toLowerCase() != 'bearer') {
      throw OidcException(OidcErrorCode.provider,
          reason: 'unsupported token_type');
    }
    if (ei != null && (ei is! num || !ei.isFinite || ei < 0)) {
      throw OidcException(OidcErrorCode.provider, reason: 'invalid expires_in');
    }
    final expiresIn = ei is num ? ei : 0;
    final nowSec = _now().microsecondsSinceEpoch / 1e6;
    return TokenSet(
      accessToken: at,
      tokenType: tt,
      expiresIn: expiresIn,
      refreshToken: rt is String && rt.isNotEmpty ? rt : null,
      idToken: it is String && it.isNotEmpty ? it : null,
      scope: scope is String ? scope : null,
      expiresAt: dateFromSeconds(nowSec + expiresIn),
    );
  }

  /// Verifies the ID-token signature and then its claims: exact issuer,
  /// audience containing this client, azp for multi-audience tokens,
  /// expiry, issued-at, nonce and at_hash (OIDC-016). The payload is never
  /// trusted before the signature.
  ///
  /// [nonce] (the one sent in the authorization request) must match when
  /// given; [accessToken] is checked against at_hash when the token has one;
  /// [maxAge] requires auth_time no older than that.
  Future<IdTokenClaims> validateIdToken(
    String raw, {
    String? nonce,
    String? accessToken,
    Duration? maxAge,
    CancelToken? cancelToken,
  }) async {
    OidcException bad(String reason) =>
        OidcException(OidcErrorCode.idToken, reason: reason);
    if (raw.isEmpty || raw.length > 16384) throw bad('size');
    final ParsedJws jws;
    try {
      jws = parseCompactJws(raw);
    } on JwsParseException catch (e) {
      throw bad(
          e.reason == JwsFailure.duplicate ? 'duplicate member' : 'malformed');
    }
    final header = jws.header;
    if (header.containsKey('crit')) throw bad('critical header');
    final alg = header['alg'];
    if (alg is! String || !_algorithms.contains(alg)) throw bad('algorithm');
    if (header.containsKey('typ')) {
      final typ = header['typ'];
      // An access token (at+jwt) is not an ID token.
      if (typ is! String || typ.toLowerCase() != 'jwt') throw bad('type');
    }
    final kid = header['kid'];
    if (kid is! String || kid.isEmpty) throw bad('missing kid');
    final jwks = await _keySet(cancelToken);
    final VerificationKey key;
    try {
      key = await jwks.getKey(kid, cancelToken);
    } on JwksException catch (e) {
      if (e.reason == JwksFailure.unknownKey) throw bad('unknown key');
      throw OidcException(OidcErrorCode.provider,
          reason: 'key set unavailable', cause: e);
    }
    if (key.alg != null && key.alg != alg) throw bad('algorithm');
    if (!verifySignature(alg, key.material, jws.signingInput, jws.signature)) {
      throw bad('signature');
    }

    final p = jws.payload;
    String? optStr(String k) {
      final v = p[k];
      if (v == null) return null;
      if (v is! String) throw bad('claim $k');
      return v;
    }

    num? optNum(String k) {
      final v = p[k];
      if (v == null) return null;
      if (v is! num || !v.isFinite) throw bad('claim $k');
      return v;
    }

    final List<String> audience;
    final aud = p['aud'];
    if (aud is String) {
      audience = [aud];
    } else if (aud is List<Object?> && aud.every((a) => a is String)) {
      audience = aud.cast<String>();
    } else {
      throw bad('audience');
    }
    final iss = optStr('iss');
    final sub = optStr('sub');
    final azp = optStr('azp');
    final exp = optNum('exp');
    final iat = optNum('iat');
    final authTime = optNum('auth_time');
    final tokenNonce = optStr('nonce');
    final atHash = optStr('at_hash');
    final nowSec = _now().microsecondsSinceEpoch / 1e6;
    final skewSec = _skew.inMicroseconds / 1e6;
    if (iss != _issuer) throw bad('issuer');
    if (sub == null || sub.isEmpty) throw bad('subject');
    if (!audience.contains(_clientId)) throw bad('audience');
    if (audience.length > 1 && azp != _clientId) throw bad('authorized party');
    if (azp != null && azp != _clientId) throw bad('authorized party');
    if (exp == null || nowSec > exp + skewSec) throw bad('expired');
    if (iat != null && iat > nowSec + skewSec) {
      throw bad('issued in the future');
    }
    if (nonce != null &&
        nonce.isNotEmpty &&
        (tokenNonce == null || !_safeEqual(tokenNonce, nonce))) {
      throw OidcException(OidcErrorCode.nonce);
    }
    if (accessToken != null &&
        accessToken.isNotEmpty &&
        atHash != null &&
        !_safeEqual(atHash, halfHash(alg, accessToken))) {
      throw bad('at_hash');
    }
    if (maxAge != null &&
        (authTime == null ||
            nowSec - authTime > maxAge.inMicroseconds / 1e6 + skewSec)) {
      throw bad('max_age');
    }
    final amr = p['amr'];
    return IdTokenClaims._(
      issuer: iss!,
      subject: sub,
      audience: List.unmodifiable(audience),
      expiry: dateFromSeconds(exp),
      issuedAt: iat != null ? dateFromSeconds(iat) : null,
      authTime:
          authTime != null && authTime > 0 ? dateFromSeconds(authTime) : null,
      nonce: tokenNonce,
      acr: optStr('acr'),
      amr: List.unmodifiable(
          amr is List<Object?> ? amr.whereType<String>() : const <String>[]),
      azp: azp,
      sid: optStr('sid'),
      atHash: atHash,
      email: p['email'] is String ? p['email']! as String : null,
      name: p['name'] is String ? p['name']! as String : null,
      claims: Map.unmodifiable(p),
    );
  }

  Future<JwksCache> _keySet(CancelToken? cancelToken) async {
    final existing = _jwks;
    if (existing != null) return existing;
    final url = await _endpoint('jwks_uri', cancelToken);
    return _jwks ??= JwksCache(
      url: url,
      client: _client,
      timeout: _timeout,
      minRefreshInterval: _minRefresh,
      now: _now,
    );
  }

  /// Wraps tokens in a [Session] with single-flight refresh. Keep exactly
  /// one Session per browser session in this process.
  ///
  /// - [idClaims]: claims of the ID token from login; refreshed ID tokens
  ///   must keep the same subject.
  /// - [onRefresh]: called after every successful refresh so the new
  ///   (rotated) tokens can be persisted server-side. Refresh tokens rotate;
  ///   persisting the old one and using it again is reuse and revokes the
  ///   whole family.
  /// - [refreshWindow]: refresh when the access token expires within this
  ///   window (default 15 s).
  Session session(
    TokenSet tokens, {
    IdTokenClaims? idClaims,
    FutureOr<void> Function(TokenSet tokens)? onRefresh,
    Duration refreshWindow = const Duration(seconds: 15),
  }) =>
      Session._(this, tokens, idClaims, onRefresh, refreshWindow);

  /// Revokes a token at the provider (RFC 7009); used at logout. An empty
  /// token is a no-op.
  Future<void> revoke(
    String token, {
    TokenTypeHint tokenTypeHint = TokenTypeHint.refreshToken,
    CancelToken? cancelToken,
  }) async {
    if (token.isEmpty) return;
    final ep = await _endpoint('revocation_endpoint', cancelToken);
    final headers = <String, String>{
      'content-type': 'application/x-www-form-urlencoded',
      'accept': 'application/json',
    };
    final form = <String, String>{
      'token': token,
      'token_type_hint': tokenTypeHint.value,
    };
    final secret = _clientSecret;
    if (secret != null) {
      headers['authorization'] = basicAuthorization(_clientId, secret);
    } else {
      form['client_id'] = _clientId;
    }
    final HttpResult res;
    try {
      res = await sendRequest(
        _client,
        method: 'POST',
        url: ep,
        headers: headers,
        body: utf8.encode(formBody(form)),
        timeout: _timeout,
        cancelToken: cancelToken,
        maxBodyBytes: _maxProviderResponseBytes,
        readBody: (_) => false,
      );
    } catch (cause) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'revocation endpoint unreachable', cause: cause);
    }
    if (res.status != 200) {
      throw OidcException(OidcErrorCode.provider,
          reason: 'revocation failed', status: res.status);
    }
  }

  /// Builds an RP-initiated logout URL.
  Future<String> logoutUrl({
    String? idTokenHint,
    String? postLogoutRedirectUri,
    String? state,
    CancelToken? cancelToken,
  }) async {
    final ep = await _endpoint('end_session_endpoint', cancelToken);
    final q = <String, List<String>>{
      for (final e in ep.queryParametersAll.entries) e.key: [...e.value],
    };
    if (idTokenHint != null && idTokenHint.isNotEmpty) {
      q['id_token_hint'] = [idTokenHint];
    }
    q['client_id'] = [_clientId];
    if (postLogoutRedirectUri != null && postLogoutRedirectUri.isNotEmpty) {
      q['post_logout_redirect_uri'] = [postLogoutRedirectUri];
    }
    if (state != null && state.isNotEmpty) q['state'] = [state];
    return ep.replace(queryParameters: q).toString();
  }

  /// Ends a session: clears it locally, revokes its refresh token and
  /// returns the RP-initiated logout URL. The local session is cleared even
  /// when revocation fails (the error is then rethrown after clearing).
  Future<String> logout(
    Session session, {
    String? postLogoutRedirectUri,
    String? state,
    CancelToken? cancelToken,
  }) async {
    final tokens = session.tokens;
    session.clear();
    final url = await logoutUrl(
      idTokenHint: tokens?.idToken,
      postLogoutRedirectUri: postLogoutRedirectUri,
      state: state,
      cancelToken: cancelToken,
    );
    final rt = tokens?.refreshToken;
    if (rt != null && rt.isNotEmpty) {
      await revoke(rt,
          tokenTypeHint: TokenTypeHint.refreshToken, cancelToken: cancelToken);
    }
    return url;
  }
}

/// Server-side tokens for one browser session. Refresh is single-flight:
/// concurrent callers share one refresh request, so the same refresh token
/// is never presented twice (SES-009, TEST-030). A failed refresh clears the
/// session (a lost refresh response cannot be retried safely, §24.3): the
/// user must authenticate again.
///
/// Single-flight is per process (per isolate). With several BFF instances,
/// route a session to one instance or serialize refresh with a distributed
/// lock.
final class Session {
  Session._(this._client, this._tokens, this._idClaims, this._onRefresh,
      this._window);

  final OidcClient _client;
  TokenSet? _tokens;
  IdTokenClaims? _idClaims;
  Future<String>? _inflight;
  final FutureOr<void> Function(TokenSet tokens)? _onRefresh;
  final Duration _window;
  int _refreshCount = 0;

  /// Current tokens, or null after logout or a failed refresh.
  TokenSet? get tokens => _tokens;

  IdTokenClaims? get idClaims => _idClaims;

  /// Refresh requests made by this session (diagnostics and tests).
  int get refreshCount => _refreshCount;

  /// Forgets the tokens locally (does not revoke; see [OidcClient.logout]).
  void clear() => _tokens = null;

  /// Returns a valid access token, refreshing once when it is about to
  /// expire. Pass [rejectedToken] when an API rejected the current access
  /// token to force one refresh; concurrent callers that saw the same token
  /// share it.
  Future<String> accessToken({
    String? rejectedToken,
    CancelToken? cancelToken,
  }) {
    OidcException aborted() =>
        OidcException(OidcErrorCode.provider, reason: 'aborted');
    final inflight = _inflight;
    if (inflight != null) return waitFor(inflight, cancelToken, aborted);
    final t = _tokens;
    if (t == null) {
      return Future.error(OidcException(OidcErrorCode.reauthenticate));
    }
    final forced = rejectedToken != null && rejectedToken == t.accessToken;
    if (!forced && _client._now().add(_window).isBefore(t.expiresAt)) {
      return Future.value(t.accessToken);
    }
    final rt = t.refreshToken;
    if (rt == null || rt.isEmpty) {
      return Future.error(OidcException(OidcErrorCode.reauthenticate));
    }
    final p = _refresh(t, rt);
    _inflight = p;
    p.then<void>((_) {}, onError: (Object _) {}).whenComplete(() {
      if (identical(_inflight, p)) _inflight = null;
    });
    return waitFor(p, cancelToken, aborted);
  }

  Future<String> _refresh(TokenSet current, String refreshToken) async {
    final TokenSet next;
    try {
      _refreshCount++;
      // The shared refresh is bounded by the client timeout only: one caller
      // giving up must not abandon a rotation whose response the others
      // still need.
      final nt = await _client._tokenRequest(
          {'grant_type': 'refresh_token', 'refresh_token': refreshToken}, null);
      var idClaims = _idClaims;
      final idToken = nt.idToken;
      if (idToken != null) {
        final c =
            await _client.validateIdToken(idToken, accessToken: nt.accessToken);
        if (_idClaims != null && c.subject != _idClaims!.subject) {
          throw OidcException(OidcErrorCode.idToken,
              reason: 'refreshed ID token subject changed');
        }
        idClaims = c;
      }
      next = nt._merge(current);
      _idClaims = idClaims;
    } catch (err) {
      _tokens = null;
      if (err is OidcException && err.code == OidcErrorCode.reauthenticate) {
        rethrow;
      }
      throw OidcException(
        OidcErrorCode.reauthenticate,
        reason: err is OidcException ? err.code.value : 'refresh failed',
        cause: err,
      );
    }
    _tokens = next;
    final onRefresh = _onRefresh;
    if (onRefresh != null) await onRefresh(next);
    return next.accessToken;
  }
}

Map<String, List<String>> _toParams(Object callback) {
  if (callback is Uri) return callback.queryParametersAll;
  if (callback is Map<String, List<String>>) return callback;
  if (callback is Map<String, String>) {
    return callback.map((k, v) => MapEntry(k, [v]));
  }
  if (callback is String) {
    final lower = callback.toLowerCase();
    if (lower.startsWith('http://') || lower.startsWith('https://')) {
      return Uri.parse(callback).queryParametersAll;
    }
    final q = callback.indexOf('?');
    final query = q >= 0 ? callback.substring(q + 1) : callback;
    final hash = query.indexOf('#');
    return Uri(query: hash >= 0 ? query.substring(0, hash) : query)
        .queryParametersAll;
  }
  throw ArgumentError(
      'oidc-client: callback must be a Uri, a String or a parameter map');
}

bool _safeEqual(String a, String b) =>
    constantTimeEquals(utf8.encode(a), utf8.encode(b));

final RegExp _oauthCode = RegExp(r'^[a-z0-9_.-]{1,64}$', caseSensitive: false);

/// Provider error codes are echoed only when they look like OAuth error
/// codes.
String _safeCode(String s) => _oauthCode.hasMatch(s) ? s : 'unrecognized_error';
