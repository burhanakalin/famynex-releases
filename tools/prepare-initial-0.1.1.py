"""Supervised, pinned 0.1.1 initial release preparation; never activate services.

Only the CLI may provision the real fixed layout. Internal arguments exist for
isolated filesystem tests. No account, household, Core environment, login, current
link, installed identity or systemd service is created or changed here.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


PINS = {
    "version": "0.1.1",
    "sequence": 2,
    "sourceCommit": "d7d045d1d03eda1cf7e8ff201ffc45de27ab1575",
    "sourceTree": "bc7651ba92c18fba50c9ed26dd0a81277416bf35",
    "bytes": 26887751,
    "sha256": "e3ff4f108b2681e288cf631ff9a5128a29b835b764d3591c56a2b70083f276d4",
    "keyId": "famynex-release-2026-10",
    "fingerprint": "d1e786329ea234e6b35abdfb5488a8932f3a349332c20da2495ed789405f1b1e",
    "url": "https://github.com/burhanakalin/famynex-releases/releases/download/v0.1.1/famynex-linux-x64-0.1.1.tar.gz",
    "schema": 26,
}
HELPERS = (
    "linux-appliance-updater-contract.mjs", "linux-appliance-updater-service.mjs",
    "linux-appliance-updater.mjs", "linux-appliance-updater-ipc.mjs",
    "linux-appliance-updater-store.mjs", "linux-appliance-updater-units.mjs",
    "linux-appliance-download.mjs", "linux-appliance-release.mjs",
    "linux-appliance-stage.mjs", "linux-appliance-stage-review.mjs",
    "linux-appliance-plan.mjs", "linux-appliance-extract.py",
    "linux-appliance-backup.mjs", "linux-appliance-journal.mjs",
    "linux-appliance-installed-state.mjs", "linux-appliance-promote.mjs",
    "linux-appliance-activate.mjs", "linux-appliance-systemd.mjs",
    "linux-appliance-wait-ready.mjs",
)


class PreparationError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise PreparationError(code)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def protected_directory(path, boundary):
    path, boundary = Path(path), Path(boundary)
    require(path.is_relative_to(boundary), "BOUNDARY")
    while True:
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o7022, "PARENT")
        if path == boundary:
            return
        path = path.parent


def private_copy(source, destination, maximum, expected_hash=None, expected_size=None):
    # The retained user archive and public JSON are DATA. A private bounded copy
    # is authenticated before extracting even one helper or importing its code.
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, "INPUT")
        if expected_size is not None:
            require(info.st_size == expected_size, "ARCHIVE_SIZE")
        digest, size = hashlib.sha256(), 0
        with os.fdopen(os.dup(fd), "rb") as stream, open(destination, "xb") as output:
            os.fchmod(output.fileno(), 0o400)
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                require(size <= maximum, "INPUT_SIZE")
                digest.update(chunk)
                output.write(chunk)
            require(size == info.st_size, "INPUT_CHANGED")
            if expected_hash is not None:
                require(digest.hexdigest() == expected_hash, "ARCHIVE_DIGEST")
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(fd)


def extract_authenticated_helpers(archive, directory):
    # Called ONLY after exact whole-archive pin verification. No extractall,
    # links, caller-supplied output names, ownership restoration or exec bits.
    expected = {"runtime/updater/" + name: name for name in HELPERS}
    found, total, deadline = set(), 0, time.monotonic() + 120
    with tarfile.open(archive, "r:gz") as stream:
        for member in stream:
            require(time.monotonic() < deadline, "HELPER_TIME")
            name = member.name.removeprefix("./")
            if name not in expected:
                continue
            require(name not in found and member.isfile()
                    and 0 < member.size <= 512 * 1024, "HELPER")
            total += member.size
            require(total <= 2 * 1024 * 1024, "HELPER_SIZE")
            source = stream.extractfile(member)
            require(source is not None, "HELPER")
            data = source.read(member.size + 1)
            require(len(data) == member.size, "HELPER_SIZE")
            with open(Path(directory) / expected[name], "xb") as output:
                os.fchmod(output.fileno(), 0o400)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            found.add(name)
    require(found == set(expected), "HELPER_MISSING")
    sync_directory(directory)


RUNNER = r"""
import { createHash, createPublicKey } from 'node:crypto';
import { mkdir, open, chmod, rmdir } from 'node:fs/promises';
import { join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readJSON, verifyRelease } from './linux-appliance-release.mjs';
import { stageRelease } from './linux-appliance-stage.mjs';
import { promoteStage } from './linux-appliance-promote.mjs';

async function sync(path) { const f = await open(path, 'r'); try { await f.sync(); } finally { await f.close(); } }
async function write(path, value) {
  const f = await open(path, 'wx', 0o600);
  try { await f.writeFile(JSON.stringify(value) + '\n'); await f.sync(); } finally { await f.close(); }
}
const refuse = () => { throw Error('REFUSED'); };
try {
  if (process.platform !== 'linux' || process.arch !== 'x64' ||
      process.getuid() !== 0 || process.versions.node.split('.')[0] !== '22') refuse();
  const work = fileURLToPath(new URL('../', import.meta.url));
  const config = await readJSON(join(work, 'inputs.json'));
  const p = config.pins, envelope = await readJSON(join(work, 'offer.json'));
  const trust = await readJSON(join(work, 'trust.json'));
  if (trust.formatVersion !== 1 || trust.keys?.length !== 1 ||
      trust.keys[0].id !== p.keyId || trust.keys[0].status !== 'active') refuse();
  const fingerprint = createHash('sha256').update(createPublicKey(trust.keys[0].publicKey)
    .export({ type: 'spki', format: 'der' })).digest('hex');
  if (fingerprint !== p.fingerprint) refuse();
  const policy = { formatVersion: 1, purpose: 'update', installedVersion: '0.0.0',
    installedSequence: 0, schemaVersion: p.schema,
    allowedOrigins: [new URL(p.url).origin], knownGoodDigests: [] };
  // Baseline zero is initial package authentication ONLY, never installed state.
  const payload = envelope.payload;
  if (payload.version !== p.version || payload.sequence !== p.sequence ||
      payload.sourceCommit !== p.sourceCommit || payload.sourceTree !== p.sourceTree ||
      payload.package?.sha256 !== p.sha256 || payload.package?.bytes !== p.bytes ||
      payload.package?.url !== p.url || payload.schema?.minSupported !== p.schema ||
      payload.schema?.maxSupported !== p.schema || payload.schema?.target !== p.schema) refuse();
  const archive = join(work, 'package.tar.gz');
  await verifyRelease({ envelope, archive, trust, policy });
  const root = config.installationRoot, updater = config.updaterRoot;
  // mkdir without recursive/exist-ok: existing/unmanaged installations are never adopted.
  await mkdir(root, { mode: 0o755 });
  await chmod(root, 0o755);
  const lock = join(root, '.famynex-install.lock');
  await mkdir(lock, { mode: 0o700 });
  await sync(root);
  // After this point failures retain the global lock for explicit review.
  await mkdir(updater, { mode: 0o700 });
  await sync(config.stateParent);
  await mkdir(join(root, 'releases'), { mode: 0o755 });
  await chmod(join(root, 'releases'), 0o755);
  const staging = join(updater, 'staging');
  await mkdir(staging, { mode: 0o700 });
  await write(join(updater, 'initial-trust.json'), trust);
  console.info('Imza ve arsiv dogrulandi. Root sahipligindeki dosyalar hazirlaniyor; birkac dakika surebilir...');
  const staged = await stageRelease({ envelope, archive, trust, policy, parent: staging });
  console.info('Root cikartma tamamlandi. Kurulum kopyasi yeniden dogrulaniyor...');
  const promoted = await promoteStage({ parent: staging, stageName: basename(staged.stagingDirectory),
    trust, policy, releasesParent: join(root, 'releases') });
  const record = { kind: 'famynex-initial-release-preparation', formatVersion: 1,
    version: p.version, sequence: p.sequence, sourceCommit: p.sourceCommit, sourceTree: p.sourceTree,
    sha256: p.sha256, releaseDirectory: promoted.releaseDirectory,
    stagingDirectory: staged.stagingDirectory, trustBootstrapped: true,
    rootOwned: true, independentlyRechecked: true, databaseAccessed: false,
    configurationInstalled: false, servicesStarted: false, installed: false, activated: false };
  await write(join(updater, 'initial-preparation.json'), record);
  await sync(updater);
  await rmdir(lock);
  await sync(root);
  console.info(JSON.stringify(record, null, 2));
} catch {
  console.error('Root release preparation failed. No services were started. Keep any saved operation lock for review.');
  process.exitCode = 1;
}
"""


def prepare(source_stage, trust_file, *, filesystem_root=Path("/"), pins=PINS,
            node="/usr/bin/node"):
    root = Path(filesystem_root).resolve()
    opt, state_parent = root / "opt", root / "var/lib"
    protected_directory(opt, root)
    protected_directory(state_parent, root)
    for path in (opt / "famynex", state_parent / "famynex-updater"):
        require(not os.path.lexists(path), "EXISTING_INSTALLATION")
    # New account/services/backup/live identity are separate; never infer them from
    # a staged package receipt. The existing Core/policy files are not opened.
    work = Path(tempfile.mkdtemp(prefix=".famynex-initial-", dir=opt))
    os.chmod(work, 0o700)
    try:
        stage = Path(source_stage)
        private_copy(stage / "package.tar.gz", work / "package.tar.gz", pins["bytes"],
                     pins["sha256"], pins["bytes"])
        private_copy(stage / "offer.json", work / "offer.json", 65536)
        private_copy(trust_file, work / "trust.json", 65536)
        code = work / "code"
        code.mkdir(mode=0o700)
        extract_authenticated_helpers(work / "package.tar.gz", code)
        with open(code / "prepare.mjs", "x") as output:
            os.fchmod(output.fileno(), 0o400)
            output.write(RUNNER)
            output.flush()
            os.fsync(output.fileno())
        with open(work / "inputs.json", "x") as output:
            os.fchmod(output.fileno(), 0o400)
            json.dump({"pins": pins, "installationRoot": str(opt / "famynex"),
                       "updaterRoot": str(state_parent / "famynex-updater"),
                       "stateParent": str(state_parent)}, output)
            output.flush()
            os.fsync(output.fileno())
        sync_directory(work)
        child = subprocess.Popen([node, str(code / "prepare.mjs")], cwd=work,
                                 env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                                 stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
        try:
            require(child.wait(timeout=2400) == 0, "VERIFICATION")
        except BaseException:
            # Also stop a Python extractor child; never leave a writer running
            # after the supervising command times out or is interrupted.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise
    except BaseException:
        # Root-owned work is retained for review. No user-supplied path is removed.
        raise
    else:
        shutil.rmtree(work)
        sync_directory(opt)


def main():
    require(len(sys.argv) == 3 and sys.platform == "linux" and
            platform.machine() == "x86_64" and os.getuid() == 0, "HOST_OR_ARGUMENTS")
    os.umask(0o077)
    def interrupted(_signum, _frame):
        raise PreparationError('INTERRUPTED')
    signal.signal(signal.SIGTERM, interrupted)
    # Confirm the established host/configuration without opening secret or policy
    # contents. These files must survive preparation byte-for-byte.
    for path, mode in ((Path('/etc/famynex/core.env'), 0o600),
                       (Path('/var/lib/famynex-policy/setup-policy.json'), 0o644)):
        protected_directory(path.parent, Path('/'))
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                and metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == mode,
                'CONFIGURATION_METADATA')
    release_info = Path('/etc/os-release')
    protected_directory(release_info.parent, Path('/'))
    protected_directory(release_info.resolve().parent, Path('/'))
    info = release_info.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and not info.st_mode & 0o7022 and 0 < info.st_size <= 65536, 'OS')
    fields = dict(line.split('=', 1) for line in release_info.read_text().splitlines()
                  if '=' in line and not line.startswith('#'))
    require(fields.get('ID', '').strip('"') == 'linuxmint'
            and fields.get('VERSION_ID', '').strip('"') == '22.3', 'OS')
    node = Path("/usr/bin/node")
    protected_directory(node.resolve().parent, Path("/"))
    protected_directory(node.parent, Path("/"))
    info = node.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and not info.st_mode & 0o7022 and info.st_mode & 0o111, "NODE")
    prepare(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        code = str(error) if isinstance(error, PreparationError) else "IO"
        print("Initial release preparation failed [" + code + "]. No services were started.", file=sys.stderr)
        sys.exit(1)
