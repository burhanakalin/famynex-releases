# Famynex releases

Official distribution repository for Famynex Linux appliance release packages.

[Famynex 0.1.1](https://github.com/burhanakalin/famynex-releases/releases/tag/v0.1.1) is available as a signed Linux x64 **pre-release for supervised device validation**. Hardware acceptance and first-device installation remain pending; it is not a completed appliance installation.

The device updater verifies the release signature, supported platform/schema, archive size and SHA-256 before installation. A checksum alone does not establish release authenticity. Trust keys must be provisioned independently of downloaded packages.

This repository contains distribution material only. Application source is maintained separately. Private signing keys, device configuration, credentials, household data and browser profiles must never be uploaded here.

## Supervised initial release preparation

The standalone operator tool in `tools/prepare-initial-0.1.1.py` prepares ONLY the
previously approved 0.1.1 package in a new root-owned layout. It pins the archive,
source identity and public-key fingerprint, then uses the authenticated package's
existing verifier, bounded extractor and independent promotion reviewer.
Verify the tool's SHA-256 after copying it into a private root directory before
executing it: `bb43d53fac2b55ad5d0e32f5de77ee97d33c727e7491fac77c7cbe5b18a9c4bf`.

This is one preparation step for a supervised device, not an installer or a stable
customer release. It starts no service, creates no account/current/installed state,
does not access the household database, and does not modify the existing Core
environment or setup policy. It refuses existing installation roots; partial
preparation locks require explicit review. Initial service installation, trusted
session enrollment and actual hardware acceptance remain pending. Published
release archives and signed manifests are unchanged.

## Supervised initial Core/calendar installation

**Known supervised-device issue:** the first Core installer incorrectly expects the calendar worker to remain active when background sync is disabled. An actual device attempt stopped with `NOT_ACTIVE`, journal phase `starting`, no installed record, and both services inactive with successful exit status. Do not rerun that installer or clear its retained operation lock. A narrowly validated recovery is being prepared; the signed runtime package and root preparation remain valid.


After successful root preparation, `tools/install-core-0.1.1.mjs` is a separate,
checksum-verified operator tool. SHA-256:
`1978387af2ac7487fc0302466eea3a94f4e7851e81ca8a4f41ebdfa06dc1be8a`.

It privately binds the configured household and exact existing migration names,
requires a fresh decoded and rechecked database backup, then creates the dedicated
non-root account and fixed Core/calendar services. Installed state and boot
enablement follow actual process identity and database-ready health checks.
It preserves the existing Core environment, policy and keys, never migrates or
restores a database, and refuses unmanaged or already installed resources.
Failure locks and private attempt/backup records require explicit local review.

The new tool has focused filesystem/subprocess/worker-handoff tests; actual device
systemd/PostgreSQL16 service execution still needs operator confirmation. It does
not install the updater, enroll a browser, change login/idle/lid settings or mark
hardware acceptance complete. The release remains a supervised pre-release;
published signed package assets are unchanged.


### Corrected Core installer and explicit recovery

Use `tools/install-core-0.1.1-r2.mjs` for reviewed initial installation. SHA-256:
`3302a79aba62b655ed1c8e28f8bb739a0971475c1385f1ec5925cd4585e7dcf5`.
The old tool above remains preserved for history; do not rerun it.
When calendar background sync is disabled, r2 starts/enables Core only and verifies
that calendar remains inactive/disabled. It preserves the existing setting.

The literal `--recover-disabled-calendar` option is restricted to the observed
0.1.1 `starting` journal, absent installed state, exact unchanged release/account/
home/units/current, inactive disabled services and one protected prior attempt.
It retains the original lock, claims a nested lock, preserves the old journal and
backup, reauthenticates the release, verifies the live household and takes a fresh
decoded backup before Core startup. Process identity and database-ready health must
pass before installed-state commit and Core boot enablement. No migration/restore,
key replacement or browser enrollment occurs. Other states fail for separate review.

Source: `burhanakalin/famynex` commit `d189140b1971d116f42861ec077f482c65ff56fc`.
All 16 focused initial-install/recovery tests passed with real temporary files and
service/database doubles. Actual Toshiba recovery is still pending; this is not
hardware acceptance or updater activation. Signed release assets remain unchanged.


### Dedicated kiosk preparation after Core activation

The Toshiba operator confirmed successful r2 Core installation: installed/activated,
database ready, fresh backup verified, boot enabled, calendar intentionally disabled,
existing keys preserved. Kiosk enrollment and hardware acceptance remain pending.

`tools/prepare-kiosk-0.1.1.mjs` prepares only the dedicated account's kiosk files.
SHA-256: `d22803765c07dea1acd9e8982eea1c502954272d015ab0010a43ad3c209a2209`.
Source: `burhanakalin/famynex` commit `5a6dd42c3e84526bb960ac9bb12e34497eae939d`.
The tool requires the fixed installed 0.1.1 identity/current link, pinned signer and
independent retained-stage/published-release review, private existing browser profile,
protected executables and actual Core PID/cwd plus database-ready health. It refuses
existing unit/drop-in/autostart/configuration conflicts, preserves failure locks and
creates session files as the unprivileged dedicated account. The root-owned user
service additionally checks ConditionUser=famynex. No credentials reach the session.

This step leaves existing LightDM/burhan login and browser profile bytes unchanged;
it starts no kiosk, switches no session, does not enroll a display or accept hardware.
Four focused file/worker preparation cases and 24 existing appliance checks pass on
Mac Node22.23.2. Actual Toshiba preparation and GUI enrollment remain pending; the
runtime-build suite was unavailable locally because esbuild is absent. No signed
application assets were changed and no GitHub Actions run was requested.
