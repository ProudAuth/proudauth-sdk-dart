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
No GitHub or registry publication was performed by this staging work. Independent
CI is prepared but has not run yet for this repository.

Excluded: original .git history, actual .env/credentials, deployment state,
private screenshots/database backups, SDK caches/build output, image archives,
benchmark seeds and customer data. The original checkout was not modified.
