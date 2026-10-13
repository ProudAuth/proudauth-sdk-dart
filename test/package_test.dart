// The public libraries export what the README documents, and the package
// stays pure Dart with only the two runtime dependencies.
import 'dart:io';

import 'package:proudauth_sdk/admin.dart' as admin;
import 'package:proudauth_sdk/bounded_state.dart' as bounded;
import 'package:proudauth_sdk/introspection.dart' as introspection;
import 'package:proudauth_sdk/io.dart' as io;
import 'package:proudauth_sdk/oidc_client.dart' as oidc;
import 'package:proudauth_sdk/proudauth_sdk.dart' as all;
import 'package:proudauth_sdk/verifier.dart' as verifier;
import 'package:test/test.dart';

void main() {
  test('every module exports its documented entry points', () {
    // Referencing the symbols is the check: this file only compiles when
    // they are exported.
    final symbols = <Object>[
      verifier.Verifier.new,
      verifier.MultiIssuerVerifier.new,
      verifier.Claims.new,
      verifier.VerifierException.new,
      verifier.bearerToken,
      verifier.authorizeBearer,
      verifier.authenticateAuthorization,
      verifier.challenge,
      verifier.supportedAlgorithms,
      verifier.defaultAcceptedKinds,
      introspection.Introspector.new,
      introspection.SupportGuard.new,
      introspection.SupportAuditor.from,
      introspection.protectedOperations,
      introspection.writeSegments,
      introspection.isProtectedOperation,
      introspection.isWriteOperation,
      introspection.defaultOnlineKinds,
      bounded.BoundedState.new,
      bounded.BoundedVerifier.new,
      bounded.CursorExpiredException.new,
      oidc.OidcClient.new,
      oidc.OidcException.new,
      oidc.pkceChallenge,
      oidc.randomValue,
      oidc.halfHash,
      admin.AdminClient.new,
      admin.ProblemException.new,
      admin.AdminRequestException.new,
      admin.Secret.new,
      admin.newIdempotencyKey,
      io.protect,
      io.protectOperation,
      io.authenticateHttpRequest,
      io.claimsOf,
      io.sendChallenge,
      all.Verifier.new,
      all.AdminClient.new,
    ];
    expect(symbols, everyElement(isNotNull));
    // One exception and one cancellation type shared by every module.
    expect(
        identical(verifier.VerifierException, introspection.VerifierException),
        isTrue);
    expect(identical(verifier.CancelToken, admin.CancelToken), isTrue);
    expect(identical(oidc.CancelToken, bounded.CancelToken), isTrue);
  });

  test('is a pure-Dart package with two runtime dependencies', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    expect(pubspec, contains('name: proudauth_sdk'));
    expect(pubspec, contains('publish_to: none'));
    expect(pubspec, isNot(contains('flutter')));
    final deps = RegExp(r'^dependencies:\n((?:  .+\n)+)', multiLine: true)
        .firstMatch(pubspec)![1]!
        .trim()
        .split('\n')
        .map((l) => l.trim().split(':').first)
        .toList();
    expect(deps, ['crypto', 'http']);
    expect(File('LICENSE').readAsStringSync(), contains('Apache License'));
  });

  test('the library never imports dart:io outside the io adapter', () {
    for (final f
        in Directory('lib').listSync(recursive: true).whereType<File>()) {
      if (!f.path.endsWith('.dart')) continue;
      final usesIo = f.readAsStringSync().contains("import 'dart:io'");
      final allowed = f.path.endsWith('io_adapter.dart');
      expect(usesIo, allowed ? isTrue : isFalse, reason: f.path);
    }
  });
}
