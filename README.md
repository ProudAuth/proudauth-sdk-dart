# proudauth_sdk for Dart

> **Repository status:** public standalone source; package version 0.2.0 remains unpublished.
> No package-registry release or stable-support window is promised yet.
> [Documentation](https://proudauth.com/docs/) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

[![CI](https://github.com/proudbase/proudauth-sdk-dart/actions/workflows/ci.yml/badge.svg)](https://github.com/proudbase/proudauth-sdk-dart/actions/workflows/ci.yml)

The first-party Dart SDK for ProudAuth (spec §28, SDK-001 to SDK-009). It is
a port of the Node.js SDK in `sdk/node`, which itself ports the Go SDK in
`sdk/go`, with the same security behavior and the same error categories:

| Library | Purpose | Node.js equivalent |
| --- | --- | --- |
| `package:proudauth_sdk/verifier.dart` | Offline JWT access-token verification, `MultiIssuerVerifier`, framework-neutral request helpers (`authorizeBearer`, `bearerToken`, `challenge`) | `@proudauth/sdk/verifier` |
| `package:proudauth_sdk/introspection.dart` | Strict-online introspection and the support-access contract (`SupportGuard`) | `@proudauth/sdk/introspection` |
| `package:proudauth_sdk/bounded_state.dart` | Local verification plus revocations replayed from the session-event stream, failing closed when stale | `@proudauth/sdk/bounded-state` |
| `package:proudauth_sdk/oidc_client.dart` | Backend-for-frontend login: code + PKCE, ID-token validation, single-flight refresh, logout | `@proudauth/sdk/oidc-client` |
| `package:proudauth_sdk/admin.dart` | Typed admin API client: RFC 9457 problems, cursor pagination, idempotency, If-Match, deadlines, one-time secrets wrapped in `Secret`, deprecation reporting | `@proudauth/sdk/admin` |
| `package:proudauth_sdk/io.dart` | `dart:io` adapter: `protect` and `protectOperation` for `HttpServer` handlers | `protect` (`node:http`) |
| `package:proudauth_sdk/proudauth_sdk.dart` | Everything except the `dart:io` adapter | none |

Version 0.2.0 (`sdkVersion` in `admin.dart`), unpublished
(`publish_to: none`). Its compatibility and security-update policy are the
ones of the other SDKs in
[docs/integrations/sdk-compatibility.md](https://proudauth.com/docs/integrations/sdk-compatibility/).

- **Pure Dart, no Flutter.** Runtime dependencies: `crypto` and `http`, both
  maintained by the Dart team. No web framework dependency: the request
  helpers take a header value, and the only adapter is for `dart:io`.
- **Dart 3.4 or later** (`sdk: ^3.4.0`). Tested with Dart 3.13 only; 3.4 is
  declared, not tested. Every library except `io.dart` avoids `dart:io`.
- **Algorithms:** RS256, PS256, ES256 and EdDSA (Ed25519). The SDK never
  accepts `none` or HMAC. Signature verification is implemented in this
  package (see [Cryptography](#cryptography)).
- License: Apache-2.0.

## Sender-constrained tokens

Token-only verification and introspection reject any `cnf` claim with
`VerifierErrorCode.senderConstraint`, including malformed or unsupported
bindings. This SDK does not yet provide request-level DPoP or TLS certificate
verification. Use the Go `SenderVerifier` or a separately reviewed request
verifier for bound tokens; see the
[resource-server profile](https://proudauth.com/docs/integrations/resource-servers/#sender-constrained-tokens).

## Installation

The package is not published. Depend on it by path or from git:

```yaml
# pubspec.yaml of your service
dependencies:
  proudauth_sdk:
    path: /path/to/proudauth-sdk-dart
```

```yaml
dependencies:
  proudauth_sdk:
    git:
      url: https://github.com/proudbase/proudauth-sdk-dart.git
      ref: <tag or commit>
```

Then `dart pub get`.

## Which validation profile should I use?

Every API must decide, per operation, how fresh its view of revocation has to
be (§13.2, §28.2). Write the decision down for each route.

| Profile | Use it for | Revocation exposure |
| --- | --- | --- |
| **Offline JWT** (`Verifier`) | Ordinary, low-risk reads and writes on short-lived JWT access tokens. No per-request network call. | **Bounded by token lifetime.** A token issued before logout, session revocation, suspension or membership removal keeps working until its `exp` plus the clock skew: with the default 5-minute access tokens and 30 s skew, up to about 5.5 minutes (SES-023, TEST-034). |
| **Strict-online** (`Introspector`) | Identity administration, credential and security changes, payments and other high-risk operations, and any route that must stop at the moment of revocation. | None for new requests. Every request asks the identity provider. If the provider can't be reached, the request is **denied** (503). The SDK never falls back to offline checks and never caches a positive result (TEST-035). |
| **Support** (`SupportGuard`) | Any route that serves administrator support (impersonation) sessions. These sessions carry opaque `pa_it_…` tokens. | Strict-online, plus the support contract: the actor is preserved, the default is read-only, writes need an explicit allowlist, protected operations are always denied, and an audit record is written **before** access (IMP-006 to IMP-020). |
| **Bounded state** (`BoundedState` + `BoundedVerifier`) | APIs that verify JWTs locally but must stop accepting them within a known time after session, account, organization or membership revocation. Needs a service token with `realm.session_events.read`. | At most `maxStaleness`: revocations are replayed from the session-event stream, and when the replayed state is older than that, every check fails closed (503). |

Rules that hold in every profile:

- **Support tokens are always strict-online.** The offline `Verifier` rejects
  `impersonation_access`, and it refuses to be configured to accept it.
- **One audience per API.** Configure the exact issuer and this API's own
  audience, and never a wildcard.
- **Organization and ownership come from your data.** Compare
  `claims.orgId` with the organization of the resource as stored in your
  database (`claims.requireOrganization(row.orgId)`). Never compare it with
  an ID taken from the request.
- **`authzVersion` is only a hint.** It means something only when you compare
  it with trusted current state.
- **Bounded state follows the stream.** Call `start()` once, then keep
  `run(stop)` running (it long-polls with `sync(wait: 20 s)`). `start()` keeps
  the revocations already replayed and moves the position to now. A
  `410 cursor_expired` rewinds to the oldest retained event and throws
  `CursorExpiredException` from `sync()`; `run()` replays at once and keeps
  following. The state is fresh only after a read reaches the end of the
  stream, replays never weaken a revocation, and `user.recovery_restricted`
  is not a revocation. Cancelling `stop` ends an in-flight long poll and a
  backoff wait at once.

## Offline verification

### With any framework

`authorizeBearer` takes the `Authorization` header value and the request URI
(so `?access_token=` is refused) and returns either the verified claims or the
RFC 6750 response to send. Nothing in it depends on a framework:

```dart
import 'package:proudauth_sdk/verifier.dart';

final verifier = Verifier(
  issuer: 'https://id.example.com/realms/main', // exact; other issuers are rejected before any fetch
  audience: 'https://api.example.com/orders',   // this API only
  // jwksUrl defaults to '<issuer>/jwks'; it is never taken from a token (no jku/x5u)
);

// Inside your framework's handler:
Future<MyResponse> getOrder(MyRequest request, String id) async {
  final outcome = await authorizeBearer(
    verifier,
    authorization: request.header('authorization'),
    requestUri: request.uri,
    requiredScopes: ['orders:read'],      // 403 insufficient_scope without them
    realm: 'orders',
    onError: (e) => metrics.authFailure(e is VerifierException ? e.code.value : 'other'), // categories only
  );
  switch (outcome) {
    case AuthRejected(:final challenge):
      return MyResponse(challenge.status, challenge.body, headers: challenge.responseHeaders);
    case AuthAccepted(:final claims):
      final order = await db.orders.find(id);
      if (order == null) return MyResponse(404, '');
      try {
        claims.requireOrganization(order.orgId);   // throws VerifierException(organization)
      } on VerifierException catch (e) {
        final ch = challenge(e);                   // 403 insufficient_scope
        return MyResponse(ch.status, ch.body, headers: ch.responseHeaders);
      }
      return MyResponse.json(order);
  }
}
```

`bearerToken(header, requestUri: uri)` and
`authenticateAuthorization(authenticator, header)` are the smaller building
blocks; `bearerTokenFromValues` takes every value of a repeated header (more
than one `Authorization` header is `invalid_request`).

### With `dart:io`

```dart
import 'dart:io';

import 'package:proudauth_sdk/io.dart';
import 'package:proudauth_sdk/verifier.dart';

Future<void> main() async {
  final verifier = Verifier(issuer: issuer, audience: audience);
  final server = await HttpServer.bind(InternetAddress.anyIPv4, 8080);
  server.listen(protect(
    verifier,
    (request, claims) async {
      final order = await db.orders.find(request.uri.pathSegments.last);
      try {
        claims.requireOrganization(order.orgId);
      } on VerifierException catch (e) {
        return sendChallenge(request.response, challenge(e)); // 403
      }
      request.response.write(jsonEncode(order));
      await request.response.close();
    },
    requiredScopes: ['orders:read'],
    realm: 'orders',
    onError: (e, request) => log.info('auth failure', {'code': (e as VerifierException?)?.code.value}),
  ));
}
```

The handler only runs with verified claims (also available as
`claimsOf(request)`). A handler that throws gets a 500 (`onHandlerError`
reports it).

### Multiple issuers

An application that accepts tokens from several realms registers each issuer
with its own tenant (INT-009). A token from any other issuer is rejected with
`VerifierException(issuer)`, even when it is validly signed. Key your records
by tenant and subject, never by email:

```dart
final multi = MultiIssuerVerifier({
  'https://id.example.com/realms/acme': IssuerRegistration(
      verifier: Verifier(issuer: 'https://id.example.com/realms/acme', audience: audience), tenant: 'acme'),
  'https://id.example.com/realms/globex': IssuerRegistration(
      verifier: Verifier(issuer: 'https://id.example.com/realms/globex', audience: audience), tenant: 'globex'),
});
final TenantClaims(:claims, :tenant) = await multi.verifyTenant(rawToken);
```

`MultiIssuerVerifier` is an `Authenticator` too, but `authenticate()` does not
pass the tenant on.

### Responses

The helpers answer according to RFC 6750 (`challenge(error)`):

| Outcome | Status | `WWW-Authenticate` |
| --- | --- | --- |
| No bearer token | 401 | `Bearer` (no error code; `realm="…"` when configured) |
| `access_token` in the query string (TOK-023), or several `Authorization` headers | 400 | `Bearer error="invalid_request"` |
| Invalid, expired or wrong-audience token, ID token, unknown key, and so on | 401 | `Bearer error="invalid_token"` |
| Missing scope (`requiredScopes`) | 403 | `Bearer error="insufficient_scope", scope="…"` |
| Organization mismatch | 403 | `Bearer error="insufficient_scope"` |
| Support-policy denial | 403 | none |
| JWKS, introspection, event stream or audit store unavailable; stale bounded state | 503 | none (fails closed) |
| Misconfiguration (support contract) or an unexpected error | 500 | none |

Every failure response carries `cache-control: no-store` and a short
plain-text body without token material (`AuthChallenge.responseHeaders` and
`AuthChallenge.body`).

You can also verify a token directly: `await verifier.verify(rawToken)`
returns immutable `Claims` (`subject`, `audience`, `clientId`, `scopes`,
`orgId`, `sessionId`, `tokenKind`, `actor`, `expiry`, …) or throws a
`VerifierException` whose `code` is a `VerifierErrorCode`. `code.value` is the
category string shared with the Go and Node.js SDKs and the fixtures
(`missing_token`, `malformed`, `issuer`, `audience`, `expired`, …).

## Strict-online, support-aware API

```dart
import 'dart:io';

import 'package:proudauth_sdk/introspection.dart';
import 'package:proudauth_sdk/io.dart';

final introspector = Introspector(
  endpoint: 'https://id.example.com/realms/main/oauth/introspect',
  clientId: env['ORDERS_RS_CLIENT_ID']!,         // a confidential client registered as this resource server
  clientSecret: env['ORDERS_RS_CLIENT_SECRET']!, // sent with client_secret_basic, never logged
  issuer: 'https://id.example.com/realms/main',
  audience: 'https://api.example.com/orders',
  timeout: const Duration(seconds: 3),           // a timeout denies the request, it doesn't downgrade
);

final guard = SupportGuard(
  introspector: introspector,
  // Called BEFORE access for every support request, allowed or denied. If it throws, access is denied.
  auditor: SupportAuditor.from((ev, cancelToken) async {
    await db.supportAudit.insert({
      'grant_id': ev.grantId, 'actor': ev.actor, 'subject': ev.subject, 'org_id': ev.orgId,
      'operation': ev.operation, 'allowed': ev.allowed, 'deny_reason': ev.denyReason?.value,
      'at': ev.at.toIso8601String(),
    });
  }),
  writeOperations: ['orders.annotate'], // the only writes allowed, and only for allowlisted_write grants
);

// One introspection per request. Ordinary tokens follow the introspector's accepted kinds;
// support tokens follow the support contract. Routing uses the authoritative token_kind, never a token prefix.
final listOrders = protectOperation(guard, (request, claims) async {
  if (claims.isSupport) {
    request.response.headers.set('x-support-session', claims.impersonationGrantId); // IMP-021 indicator
  }
  // ...load data, then claims.requireOrganization(row.orgId)
  await request.response.close();
}, operation: 'orders.list', read: true);
final refund = protectOperation(guard, refundHandler, operation: 'orders.refund', read: false); // support always denied
```

- For routes that never serve support sessions, `protect(introspector, …)`
  (or `authorizeBearer(introspector, …)`) is enough. It rejects support tokens
  with 401.
- Outside `dart:io`, use `authorizeBearer(guard.operation('orders.list', read: true), …)`:
  `guard.operation(...)` is an `Authenticator` for one route operation.
- `guard.authorize(raw, operation, read: …)` accepts support tokens only.
  `guard.authorizeAny(...)` accepts both kinds and is what the route
  authenticators use.
- `read` must be `true` for an operation to count as a read. An operation
  whose name contains a write verb as a segment (`writeSegments`: `create`,
  `update`, `delete`, `cancel`, `issue` and so on) is always a write, even
  with `read: true`. Write allowlist entries match the whole operation name,
  case-insensitively.
- Protected operations (`protectedOperations`: password, MFA, identifier and
  credential changes, API-key and personal-token creation, payments, refunds,
  ownership transfer, secrets, deletes, purges) are always denied to support
  sessions. Operation names are split into segments on `.`, `:` and `/`,
  case-insensitively, and an entry matches when its segments appear anywhere
  in the name as a run, with or without a trailing `s`: `orders.delete`,
  `users.password.change`, `payments.create`, `refunds.issue`,
  `secrets.read`, `read.payments` and `orders.purge` are protected;
  `secretary.list` is not. Add more with `protectedOperations:`; the defaults
  can't be removed from a guard. A list passed as the second argument of
  `isProtectedOperation(op, list)` replaces the defaults, so pass
  `[...protectedOperations, ...yours]`. The Go and Node.js SDKs and the
  server's decision API apply the same rule; the shared cases are in
  `testdata/contracts/support-operations/cases.json`.
- When your service also calls the decision API (`POST /authorization/check`)
  with a support token as `subject_token`, keep the resource's
  `impersonation_policy.write_actions` equal to `writeOperations`.

## Bounded state

```dart
import 'package:proudauth_sdk/bounded_state.dart';
import 'package:proudauth_sdk/verifier.dart';

final state = BoundedState(
  baseUrl: 'https://id.example.com',
  realm: 'main',
  token: () => serviceTokens.current(),           // admin audience, realm.session_events.read
  maxStaleness: const Duration(seconds: 60),
);
await state.start();                               // before accepting traffic
final stop = CancelToken();
unawaited(state.run(stop, onError: (e) => log.warning('session-event stream: $e')));

final authenticator = BoundedVerifier(Verifier(issuer: issuer, audience: audience), state);
// Use it like any Authenticator: 401 for revoked tokens, 503 when the state is stale.
// At shutdown: stop.cancel();
```

`sync()` and `start()` throw `VerifierException(unavailable)` for every
failure (`CursorExpiredException` for a 410). Call `start()` before `run()`
or `sync()`: without it they read the stream from its oldest retained event,
and `check()` fails closed (`stale_state`) until a sync has completed.

## Backend-for-frontend (BFF)

```dart
import 'package:proudauth_sdk/oidc_client.dart';

final oidc = OidcClient(
  issuer: 'https://id.example.com/realms/main',
  clientId: 'customer-web-bff',
  clientSecret: env['BFF_CLIENT_SECRET'],
  redirectUri: 'https://app.example.com/callback',
  scopes: ['openid', 'orders:read'],
  resource: 'https://api.example.com/orders',
);

final pendingLogins = <String, AuthRequest>{}; // server-side login state: loginId -> AuthRequest
final sessions = <String, Session>{};          // server-side sessions: sessionId -> Session (one per browser session)

// GET /login
final ar = await oidc.authorizationUrl();       // state, nonce, PKCE S256, resource
pendingLogins[loginId] = ar;                    // or persist ar.toJson() server-side
// set an HttpOnly, Secure cookie with loginId, then redirect to ar.url

// GET /callback
final ar = pendingLogins.remove(loginIdFromCookie); // single use
if (ar == null) return badRequest();
// Validates state, iss (RFC 9207), redeems the code with the PKCE verifier,
// and validates the ID token (signature, iss, aud, azp, exp, nonce, at_hash).
final (:tokens, :idClaims) = await oidc.exchangeCode(ar, request.requestedUri);
sessions[sid] = oidc.session(tokens, idClaims: idClaims, onRefresh: (t) => persist(sid, t.toJson()));

// GET /api/orders
try {
  var at = await session.accessToken();          // single-flight refresh near expiry
  var r = await http.get(ordersUri, headers: {'authorization': 'Bearer $at'});
  if (r.statusCode == 401) {                     // refresh once; concurrent callers share it
    at = await session.accessToken(rejectedToken: at);
    r = await http.get(ordersUri, headers: {'authorization': 'Bearer $at'});
  }
} on OidcException catch (e) {
  if (e.code == OidcErrorCode.reauthenticate) { sessions.remove(sid); return unauthorized(); }
  rethrow;
}

// POST /logout: clears the session, revokes the refresh token, returns the RP-initiated logout URL.
final url = await oidc.logout(session, postLogoutRedirectUri: 'https://app.example.com/');
```

**Refresh tokens rotate, and reusing one revokes the whole token family
(SES-007/008).**

- `Session.accessToken()` is single-flight. Concurrent callers share one
  refresh request, so one isolate never sends the same refresh token twice.
- If a refresh fails, the session is cleared and the error is
  `reauthenticate`. A lost refresh response can't be retried safely.
- Keep exactly one `Session` object per browser session per isolate. Persist
  rotated tokens in `onRefresh` (`TokenSet.toJson()`; `toString()` never
  prints tokens).
- If you run several BFF instances or isolates, use sticky sessions or a
  distributed lock around refresh.
- Never send refresh tokens or ID tokens to business APIs.

## Admin client

```dart
import 'package:proudauth_sdk/admin.dart';

final admin = AdminClient(
  baseUrl: 'https://id.example.com',
  realm: 'main',
  tokenSource: (cancelToken) => getAdminAccessToken(), // or token: '...'
  timeout: const Duration(seconds: 30),
  userAgent: 'billing-provisioner/3.1',                 // sent before "proudauth-sdk-dart/0.2.0"
  onDeprecated: (d) => log.warning('deprecated ProudAuth API ${d.method} ${d.path} ${d.deprecation} ${d.sunset}'),
);

await for (final user in admin.users('ann')) {          // follows next_cursor
  print(user.id);
}

try {
  await admin.createUser({'email': 'a@example.com'}, RequestOptions(idempotencyKey: savedKey)); // reuse the key when retrying
} on ProblemException catch (e) {
  print('${e.status} ${e.code} ${e.errors}');           // RFC 9457; e.type is https://auth.proudbase.com/problems/<code>
}

final got = await admin.getUser('usr_1');
await admin.updateUser('usr_1', {'display_name': 'Ann'}, RequestOptions(ifMatch: got.etag)); // 412 when stale
await admin.request('GET', '/sessions', options: RequestOptions(cancelToken: CancelToken.timeout(const Duration(seconds: 2))));
```

Transport failures throw `AdminRequestException` (`code`: `timeout`,
`aborted`, `network`, `invalidResponse`, `tokenSource`; `code.value` is the
Node.js string). The SDK never logs anything, and its error messages never
contain request bodies, tokens or secrets (SDK-008); the path in errors and
deprecation notices has no query string.

One-time secrets in response data (`client_secret`, `client_secrets`,
`api_key`, `signing_secret`, `setup_token`, `recovery_codes`,
`invitation_secret`, `access_token`, `refresh_token`, `id_token`,
`handoff_code`, `download_token`, `token`, `secret`, `webhook_secrets`, at any
depth) are `Secret` instances: `toString()` and `toJson()` (so `jsonEncode`)
give `[REDACTED]`, and `reveal()` returns the value for the one place that
must store it:

```dart
final client = await admin.createClient({'client_id': 'svc', 'name': 'Service', 'client_type': 'confidential'});
final secret = client['client_secret'];
if (secret is Secret) await vault.store('svc', secret.reveal());
print(client);                                          // {..., client_secret: [REDACTED]}
```

Every request carries `proudauth-sdk: dart/0.2.0` and a user agent ending in
`proudauth-sdk-dart/0.2.0`.

## Cancellation, timeouts and limits

Every network call takes an optional `CancelToken` (`cancelToken:`), the
counterpart of the Node.js SDK's `AbortSignal`. Cancelling it stops that
caller's request or wait; shared work (a coalesced key-set fetch, a
single-flight refresh) continues for the other callers.
`CancelToken.timeout(duration)` cancels itself.

| Operation | Timeout | Response limit |
| --- | --- | --- |
| JWKS fetch (verifier, ID tokens) | 5 s verifier, 10 s OIDC client | 1 MiB |
| Introspection | 3 s | 64 KiB |
| OIDC discovery, token and revocation endpoints | 10 s | 1 MiB |
| Admin requests | 30 s (per request: `RequestOptions.timeout`) | 32 MiB |
| Session-event stream | 30 s per request (long polls wait at most 25 s) | 8 MiB per page |

Tokens larger than 8192 bytes are rejected by the verifier and the
introspector without a network call; ID tokens are limited to 16384
characters. No request follows redirects (a 3xx is a failure; on the Dart VM, since browsers follow redirects themselves), endpoint URLs
must be absolute `http` or `https` URLs without credentials (use `https` in
production; the SDK, like the Node.js one, does not refuse `http` so that it
can be tested locally), and every object that makes requests accepts an
`httpClient:` (proxies, tests) and has `close()`, which closes the client it
created itself (not one you passed in).

## Security properties (offline verifier)

The `Verifier` implements the §14.4 algorithm:

1. **Issuer first.** The payload's `iss` must equal the configured issuer
   before any key lookup. Tokens from other issuers never trigger a network
   fetch (TEST-003).
2. **Strict parsing.**
   - Tokens over 8192 bytes are rejected.
   - The token must have exactly three canonical base64url segments, with no
     padding and nothing trailing.
   - Duplicate JSON member names are rejected in the header and the payload,
     including escaped duplicates (Dart's `jsonDecode` keeps the last member,
     so the SDK has its own RFC 8259 parser).
   - Nesting deeper than 32 levels, lone surrogates, invalid UTF-8 and a BOM
     are rejected.
   - A `crit` header is rejected.
3. **Typing.** `typ` must be `at+jwt` or `application/at+jwt`
   (case-insensitive), so ID tokens are refused (TEST-002).
4. **Algorithm allowlist.** Only RS256, PS256, ES256 and EdDSA are accepted.
   - The SDK refuses to configure `none` or `HS*`.
   - The key type must match the algorithm, and a JWK `alg`, when present,
     must match the header.
   - RSA keys must be at least 2048 bits.
5. **Keys only from the configured JWKS.**
   - `jku`, `x5u` and an embedded `jwk` are ignored.
   - JWKS entries that are private, symmetric, not for signing, off the
     curve, or ambiguous (duplicate `kid`) are skipped.
   - An unknown `kid` triggers at most one coalesced refresh per
     `minRefreshInterval` (default 30 s). Floods of random key IDs cause a
     bounded number of fetches (`verifier.fetchCount`, TEST-005).
   - If a refresh fails, the known keys are kept.
6. **Claims.**
   - The token must have exactly one audience, equal to the configured one
     (TEST-001).
   - `exp` is required. `nbf` and `iat` are checked when present. Clock skew
     defaults to 30 s and can't exceed 60 s (TEST-006).
   - `sub`, `client_id` and `jti` are required.
   - `token_kind` must be in the allowlist. The default is `user_access`,
     `service_access` and `exchange_access`.
7. **Fail closed.** Every failure throws, and a key-set outage becomes
   `unavailable` (503).

## Cryptography

No public-key library is used: signature **verification** for the four
algorithms is implemented in `lib/src/internal/crypto` with `BigInt` and the
SHA-256/SHA-512 of `package:crypto`. The library contains no signing code
and handles no private keys. The arithmetic is variable-time, which is
acceptable because every input of a verification (key, message, signature) is
public; do not reuse this code for anything else.

- **RS256** (RSASSA-PKCS1-v1_5): the signature must be exactly as long as the
  modulus and below it; the complete expected encoding (SHA-256 DigestInfo
  with NULL parameters only) is rebuilt and compared, never parsed. Keys:
  2048 to 16384 bits, odd modulus, odd exponent with 3 <= e < n.
- **PS256** (RSASSA-PSS): SHA-256, MGF1-SHA-256 and a 32-byte salt (JWA; the
  Node.js SDK enforces the same), signature exactly as long as the modulus.
- **ES256** (ECDSA P-256): 64-byte `r || s` only (DER is refused),
  `1 <= r, s < n`; JWK coordinates must be 32 bytes, below p and on the
  curve (the cofactor is 1). High-S signatures are valid, as in every ECDSA
  verifier.
- **EdDSA** (Ed25519, RFC 8032): strict point decoding (y < p, no negative
  zero), canonical S (`S < L`), and the cofactorless equation, checked by
  comparing the encoding of `[S]B - [k]A` with R, as OpenSSL (the Node.js
  SDK) and Go do. Small-order keys are not rejected: the key set is trusted
  configuration.

Tests: the shared fixtures (RS256, EdDSA), independent vectors generated with
Go's standard library in [test/vectors](test/vectors/README.md) (RS256,
PS256, ES256 and Ed25519, including RFC 8032 section 7.1 tests 1 to 3 and
negative cases), and complete ES256 and PS256 tokens signed by Go.

## Intentional differences from the Node.js SDK

The Dart SDK follows the Node.js SDK. The differences are Dart conventions or
places where Dart needs its own answer:

- **Names and types.** `VerifierException`, `OidcException`,
  `ProblemException` and `AdminRequestException` implement `Exception`
  (Node.js `VerifierError`, `OIDCError`, `ProblemError`,
  `AdminRequestError`); codes are enums whose `value` is the Node.js string.
  `OidcClient`, `IdTokenClaims`, `isSupport` (a getter),
  `requireScope(scope)` / `requireScopes(list)`. Durations are `Duration`,
  clocks are `DateTime Function()`, cancellation is `CancelToken` instead of
  `AbortSignal`, and configuration errors throw `ArgumentError` (Node.js
  `TypeError`).
- **Adapters.** No Express, Connect or Fastify adapters. The framework-neutral
  `authorizeBearer` and the `dart:io` `protect` / `protectOperation` replace
  `middleware`, `protect`, `fastifyHook` and `guard.middleware`;
  `requiredScopes:` replaces the `requireScopes` middleware, and
  `claimsOf(request)` replaces `getClaims(req)` / `req.auth`.
- **SupportGuard.** The introspector and the auditor are required,
  non-nullable constructor arguments, so a guard without the contract cannot
  be built and there is no run-time `validate()`.
- **Bounded state.** Every failure of `start()` and `sync()` is a
  `VerifierException(unavailable)` (Node.js lets network, token-source and
  JSON errors through as they are). Requests have a 30 s deadline and an
  8 MiB page limit (from the Go SDK; Node.js has neither). A page with a
  malformed event, such as an unparsable `occurred_at`, is rejected as a
  whole instead of being applied with an invalid time. A failing `onError`
  callback does not stop `run()`. `baseUrl` is validated. Like Node.js (and
  unlike Go), there is no not-started guard.
- **PS256 signature length.** A PS256 signature shorter than the modulus
  (leading zero bytes stripped) is rejected, as RFC 8017 and Go require;
  OpenSSL, under the Node.js SDK, accepts it. Spec-compliant signers,
  ProudAuth included, always produce full-length signatures.
- **RSA key import.** Keys with an even modulus, a modulus over 16384 bits,
  or an even, too small (< 3) or too large (>= n) exponent are skipped
  (`unknown_key`); OpenSSL imports some of them and then fails every
  signature (`signature`).
- **Persistence helpers.** `AuthRequest` and `TokenSet` have `toJson()` /
  `fromJson()` for server-side storage, and their `toString()` never prints
  tokens or the PKCE verifier.
- **Admin client.** A `null` body means no body (Node.js `undefined`); typed
  models (`User`, `Organization`, …) are read-only views over the JSON map
  (`data`); `setUserState` takes a `UserStateAction`, `assign` takes `Ref`s,
  and `rotateClientSecret` takes a `Duration`. The SDK headers name Dart:
  `proudauth-sdk: dart/0.2.0`, `proudauth-sdk-dart/0.2.0`.
- **OIDC provider responses over 1 MiB** are reported as invalid responses
  (`invalid metadata`, `invalid token response`); for an error response of
  the token endpoint, Node.js ignores the body and reports the status.

## Development

```sh
dart pub get                          # dev dependencies: lints, test
dart analyze                          # package:lints recommended rules plus strict casts/inference/raw types
dart format --set-exit-if-changed .
dart test
```

The tests run against in-process `HttpServer` mocks and `package:http`'s
`MockClient`, and need no network. Tokens are minted at test time by a
test-only signer (`test/support/signer.dart`), the counterpart of the Node.js
tests' `node:crypto` helpers. The suites port every Node.js test file:

- `fixtures_test.dart` runs every case of
  [`testdata/contracts/access-tokens/cases.json`](testdata/contracts/README.md) (the 22
  tokens shared with the Go and Node.js SDKs: exactly the two `accept` cases
  are accepted, every other case reports its expected category), and
  `support_operations_test.dart` runs every case of
  `testdata/contracts/support-operations/cases.json` through
  `isProtectedOperation`, `isWriteOperation` and `SupportGuard`;
- `crypto_vectors_test.dart` runs the Go-generated RS256, PS256, ES256 and
  Ed25519 vectors and the RFC 8032 tests;
- `verifier_test.dart`, `multi_issuer_test.dart`, `introspection_test.dart`,
  `bounded_state_test.dart`, `oidc_client_test.dart`, `admin_test.dart`,
  `middleware_test.dart` and `json_test.dart` cover the same negative
  scenarios as the Node.js suites: wrong issuer without a fetch, wrong
  audience, `none`, HS256 key confusion, ID tokens as access tokens, expiry
  and skew, duplicate claims, the unknown-`kid` flood, oversized tokens,
  impersonation tokens used offline, introspection fail-closed behavior and
  the support contract with audit-before-access, bounded-state replay and
  410 recovery, OIDC state, `iss`, nonce and `at_hash` checks, single-flight
  refresh against an IdP that revokes the token family on reuse, admin
  problems, pagination, idempotency, deadlines and secret redaction;
- `package_test.dart` checks the public exports, the two runtime
  dependencies and that only `io.dart` uses `dart:io`.
