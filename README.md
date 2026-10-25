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
