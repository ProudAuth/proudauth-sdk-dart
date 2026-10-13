# Standalone validation — 2026-10-13

Source checkout HEAD: `5ff6ddb852b572a05d4b1b5e6afdf2ecc1350a11`.
SOURCE-MANIFEST.json records working-tree input hashes, including unpublished
changes; it does not assert that the input bytes equal that commit. The vendored
contracts/vectors are pinned separately in testdata/manifest.json.

Runtime: **Dart 3.13.3, macos_arm64**.

Contract hashes (4 files): pass. dart pub get --offline: pass. dart analyze: no issues. Formatting: **42 files, 0 changes** after formatting the two relocated fixture paths. dart test: **216 passed, 0 failed**.

Dependency lockfile retained. publish_to: none retained. Dart 3.4 is declared but was not tested; development test dependencies require a newer runtime.

All restores used existing local caches with network package/module downloads
disabled. No Docker, database or public deployment was used; tests use synthetic
data and loopback mock servers. Commands: python3 scripts/check-contracts.py;
the standalone README and CI contain the build/test commands. npm used --offline;
Dart used pub get --offline; .NET used only local feeds and NuGetAudit=false.

Generated build outputs/dependencies and temporary consumer directories were
removed after verification. Dependency lockfiles and synthetic vectors remain.
Final documentation/repository metadata edits do not change runtime behavior.
The staging validation preceded source publication. The reviewed source is now
public at [`proudbase/proudauth-sdk-dart`](https://github.com/proudbase/proudauth-sdk-dart).
The [initial independent CI run](https://github.com/proudbase/proudauth-sdk-dart/actions/runs/38454443159)
passed at commit `9e119bc1a02c5380941c124a8bf8ef52541109ba` on Dart 3.13.3 on Ubuntu 24.04.
Locked restore, analysis, formatting and all 216 tests passed.
GitHub private vulnerability reporting is enabled. No package-registry release
or SDK release tag has been published.

Excluded: original .git history, actual .env/credentials, deployment state,
private screenshots/database backups, SDK caches/build output, image archives,
benchmark seeds and customer data. The original checkout was not modified.
