// Prepare the dedicated kiosk files only; no login switch or enrollment.
import { spawn } from 'node:child_process';
import { createHash, createPublicKey } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readlink, realpath, rmdir } from 'node:fs/promises';
import { dirname, join, resolve, basename } from 'node:path';
import { pathToFileURL } from 'node:url';
export const approval = Object.freeze({
  version: '0.1.1',
  sequence: 2,
  schema: 26,
  sourceCommit: 'd7d045d1d03eda1cf7e8ff201ffc45de27ab1575',
  sourceTree: 'bc7651ba92c18fba50c9ed26dd0a81277416bf35',
  sha256: 'e3ff4f108b2681e288cf631ff9a5128a29b835b764d3591c56a2b70083f276d4',
  keyId: 'famynex-release-2026-10',
  fingerprint: 'd1e786329ea234e6b35abdfb5488a8932f3a349332c20da2495ed789405f1b1e'
});
const minimal = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
export class KioskPreparationError extends Error {
  constructor(code) {
    super(`Kiosk preparation failed [${code}]. Keep existing files and operation lock for review.`);
    this.code = code;
  }
}
const fail = (code) => {
  throw new KioskPreparationError(code);
};
export async function command(
  program,
  args,
  { timeoutMs = 15000, allowed = [0], env = minimal } = {}
) {
  return new Promise((done, reject) => {
    const child = spawn(program, args, {
      shell: false,
      detached: true,
      env,
      stdio: ['ignore', 'pipe', 'ignore']
    });
    const chunks = [];
    let size = 0,
      failed = false;
    const stop = () => {
      failed = true;
      if (child.pid) {
        try {
          process.kill(-child.pid, 'SIGKILL');
        } catch {}
      }
    };
    const timer = setTimeout(stop, timeoutMs);
    child.stdout.on('data', (part) => {
      size += part.length;
      if (size > 65536) stop();
      else chunks.push(part);
    });
    child.once('error', () => {
      clearTimeout(timer);
      reject(new KioskPreparationError('COMMAND'));
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (failed || !allowed.includes(code)) reject(new KioskPreparationError('COMMAND'));
      else done({ code, stdout: Buffer.concat(chunks).toString('utf8').trim() });
    });
  });
}
async function protectedDirectory(path, root, uid) {
  let cursor = path;
  while (true) {
    const info = await lstat(cursor);
    if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== uid || info.mode & 0o7022)
      fail('PARENT');
    if (cursor === root) return;
    const parent = dirname(cursor);
    if (parent === cursor) fail('BOUNDARY');
    cursor = parent;
  }
}
async function protectedFile(path, root, uid, mode, max = 65536) {
  await protectedDirectory(dirname(path), root, uid);
  const f = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await f.stat();
    if (
      !info.isFile() ||
      info.uid !== uid ||
      info.nlink !== 1 ||
      (info.mode & 0o7777) !== mode ||
      info.size < 1 ||
      info.size > max
    )
      fail('FILE');
    return f;
  } catch (error) {
    await f.close();
    throw error;
  }
}
async function json(path, root, uid) {
  const f = await protectedFile(path, root, uid, 0o600);
  try {
    const bytes = Buffer.alloc(65537);
    const { bytesRead } = await f.read(bytes, 0, bytes.length, 0);
    if (bytesRead > 65536 || bytesRead !== (await f.stat()).size) fail('FILE');
    return JSON.parse(bytes.subarray(0, bytesRead));
  } finally {
    await f.close();
  }
}
async function sync(path) {
  const f = await open(path, 'r');
  try {
    await f.sync();
  } finally {
    await f.close();
  }
}
async function absent(path) {
  try {
    await lstat(path);
    fail('EXISTING_RESOURCE');
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
}
async function write(path, value, mode = 0o600) {
  const f = await open(path, 'wx', mode);
  try {
    await f.chmod(mode);
    await f.writeFile(value);
    await f.sync();
  } finally {
    await f.close();
  }
  await sync(dirname(path));
}

export async function prepareKiosk({
  root = '/',
  uid = process.getuid(),
  pins = approval,
  run = command,
  helpers,
  fetchHealth
} = {}) {
  root = await realpath(root);
  const at = (path) => join(root, path);
  const installation = at('opt/famynex'),
    updater = at('var/lib/famynex-updater');
  const release = join(installation, 'releases', pins.sha256);
  for (const path of [installation, updater, release, at('etc/systemd'), at('etc/xdg')])
    await protectedDirectory(path, root, uid);
  const state = await helpers.readInstalledState(join(updater, 'installed'));
  if (
    state.version !== pins.version ||
    state.sequence !== pins.sequence ||
    state.sha256 !== pins.sha256 ||
    state.sourceTree !== pins.sourceTree ||
    state.schemaVersion !== pins.schema
  )
    fail('INSTALLED_STATE');
  const current = join(installation, 'current'),
    link = await lstat(current);
  if (
    !link.isSymbolicLink() ||
    link.uid !== uid ||
    (await readlink(current)) !== `releases/${pins.sha256}`
  )
    fail('CURRENT');
  const preparation = await json(join(updater, 'initial-preparation.json'), root, uid);
  if (
    preparation.releaseDirectory !== release ||
    dirname(preparation.stagingDirectory ?? '') !== join(updater, 'staging') ||
    !/^\.famynex-stage-[A-Za-z0-9_-]{6,32}$/.test(basename(preparation.stagingDirectory))
  )
    fail('PREPARATION');
  const trust = await json(join(updater, 'initial-trust.json'), root, uid);
  if (
    trust.formatVersion !== 1 ||
    trust.keys?.length !== 1 ||
    trust.keys[0].id !== pins.keyId ||
    trust.keys[0].status !== 'active' ||
    createHash('sha256')
      .update(createPublicKey(trust.keys[0].publicKey).export({ type: 'spki', format: 'der' }))
      .digest('hex') !== pins.fingerprint
  )
    fail('TRUST');
  const user = (await run('/usr/bin/getent', ['passwd', 'famynex'])).stdout.split(':');
  if (
    user.length !== 7 ||
    user[0] !== 'famynex' ||
    !/^[1-9]\d{0,8}$/.test(user[2]) ||
    !/^[1-9]\d{0,8}$/.test(user[3]) ||
    user[5] !== '/var/lib/famynex' ||
    user[6] !== '/bin/bash'
  )
    fail('ACCOUNT');
  const accountUid = Number(user[2]),
    accountGid = Number(user[3]);
  const home = at('var/lib/famynex');
  await protectedDirectory(dirname(home), root, uid);
  for (const path of [home, join(home, 'browser')]) {
    const info = await lstat(path);
    if (
      !info.isDirectory() ||
      info.isSymbolicLink() ||
      info.uid !== accountUid ||
      info.gid !== accountGid ||
      (info.mode & 0o7777) !== 0o700 ||
      (await realpath(path)) !== path
    )
      fail('PROFILE');
  }
  const definitions = helpers.runtimePlan({});
  const userDirectory = at('etc/systemd/user');
  const configuration = join(home, '.config'),
    autostart = join(configuration, 'autostart');
  const unitPath = join(userDirectory, 'famynex-kiosk.service');
  const sessionPath = join(autostart, 'famynex-kiosk.desktop');
  const unit = definitions.userUnits['famynex-kiosk.service'].replace(
    '[Unit]\n',
    '[Unit]\nConditionUser=famynex\n'
  );
  const session = definitions.sessionFiles['famynex-kiosk.desktop'];
  const recordPath = join(updater, 'kiosk-preparation.json');
  // No adoption, even on a superficially matching rerun. Partial changes need review.
  for (const path of [
    configuration,
    unitPath,
    sessionPath,
    recordPath,
    at('etc/systemd/user/famynex-kiosk.service.d'),
    at('etc/systemd/user/famynex-kiosk.service.wants'),
    at('etc/systemd/user/famynex-kiosk.service.requires'),
    at('run/systemd/user/famynex-kiosk.service'),
    at('usr/lib/systemd/user/famynex-kiosk.service'),
    at('usr/local/lib/systemd/user/famynex-kiosk.service'),
    at('etc/xdg/autostart/famynex-kiosk.desktop')
  ])
    await absent(path);
  for (const directory of [
    'etc/systemd/user',
    'etc/systemd/user.control',
    'run/systemd/user',
    'run/systemd/user.control',
    'usr/local/lib/systemd/user',
    'usr/local/share/systemd/user',
    'usr/lib/systemd/user',
    'usr/share/systemd/user'
  ])
    for (const suffix of ['', '.d', '.wants', '.requires'])
      await absent(at(`${directory}/famynex-kiosk.service${suffix}`));
  try {
    await protectedDirectory(userDirectory, root, uid);
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    await protectedDirectory(dirname(userDirectory), root, uid);
  }
  const lock = join(installation, '.famynex-install.lock');
  try {
    await mkdir(lock, { mode: 0o700 });
  } catch (e) {
    if (e.code === 'EEXIST') fail('BUSY');
    throw e;
  }
  await sync(installation);
  // Failures retain the global lock and any new files; never reset a profile.
  const verified = await helpers.reviewStage({
    parent: join(updater, 'staging'),
    stageName: basename(preparation.stagingDirectory),
    trust,
    policy: {
      formatVersion: 1,
      purpose: 'update',
      installedVersion: '0.0.0',
      installedSequence: 0,
      schemaVersion: pins.schema,
      allowedOrigins: ['https://github.com'],
      knownGoodDigests: []
    },
    publishedDirectory: release
  });
  if (
    ['version', 'sequence', 'sourceCommit', 'sourceTree', 'sha256'].some(
      (key) => verified[key] !== pins[key]
    ) ||
    verified.targetSchema !== pins.schema ||
    verified.requiresMigration !== false
  )
    fail('RELEASE');
  const core = await helpers.serviceState('famynex-core.service');
  if (
    core.state !== 'active' ||
    core.pid < 1 ||
    (await realpath(at(`proc/${core.pid}/cwd`))) !== join(release, 'apps/web')
  )
    fail('CORE_PROCESS');
  if (!(await helpers.waitForCore({ ...(fetchHealth ? { fetchHealth } : {}), deadlineMs: 85000 })))
    fail('HEALTH');
  for (const executable of [
    'usr/bin/chromium',
    'usr/bin/xfce4-session',
    'usr/bin/flock',
    'usr/bin/zenity'
  ]) {
    const path = at(executable);
    await protectedDirectory(dirname(path), root, uid);
    const resolved = await realpath(path),
      info = await lstat(resolved);
    await protectedDirectory(dirname(resolved), root, uid);
    if (!info.isFile() || info.uid !== uid || info.mode & 0o7022 || !(info.mode & 0o111))
      fail('EXECUTABLE');
  }
  const latest = await helpers.serviceState('famynex-core.service');
  if (
    latest.state !== 'active' ||
    latest.pid !== core.pid ||
    (await readlink(current)) !== `releases/${pins.sha256}`
  )
    fail('CORE_CHANGED');
  try {
    await mkdir(userDirectory, { mode: 0o755 });
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
  }
  await protectedDirectory(userDirectory, root, uid);
  await write(unitPath, unit, 0o644);
  // The Core account owns this home. Never perform root writes through its
  // writable ancestors; create all session files in an unprivileged worker.
  const sessionCode = `import {mkdir, open} from 'node:fs/promises';
const home = ${JSON.stringify(home)};
if (process.getuid() !== ${accountUid} || process.getgid() !== ${accountGid}) process.exit(1);
for (const path of [home + '/.config', home + '/.config/autostart']) await mkdir(path, {mode: 0o700});
const f = await open(home + '/.config/autostart/famynex-kiosk.desktop', 'wx', 0o644);
try { await f.chmod(0o644); await f.writeFile(${JSON.stringify(session)}); await f.sync(); } finally { await f.close(); }
for (const path of [home + '/.config/autostart', home + '/.config', home]) {
const d = await open(path, 'r'); try { await d.sync(); } finally { await d.close(); }
}`;
  await run('/usr/sbin/runuser', [
    '-u',
    'famynex',
    '--',
    '/usr/bin/node',
    '--input-type=module',
    '--eval',
    sessionCode
  ]);
  for (const directory of [configuration, autostart]) {
    const info = await lstat(directory);
    if (
      !info.isDirectory() ||
      info.isSymbolicLink() ||
      info.uid !== accountUid ||
      info.gid !== accountGid ||
      (info.mode & 0o7777) !== 0o700 ||
      (await realpath(directory)) !== directory
    )
      fail('SESSION_DIRECTORY');
  }
  const unitInfo = await lstat(unitPath),
    sessionInfo = await lstat(sessionPath);
  if (unitInfo.uid !== uid || sessionInfo.uid !== accountUid || sessionInfo.gid !== accountGid)
    fail('OWNERSHIP');
  await write(
    recordPath,
    JSON.stringify({
      formatVersion: 1,
      version: pins.version,
      sha256: pins.sha256,
      unitSha256: createHash('sha256').update(unit).digest('hex'),
      sessionSha256: createHash('sha256').update(session).digest('hex'),
      accountUid,
      accountGid,
      loginChanged: false,
      enrolled: false
    })
  );
  await rmdir(lock);
  await sync(installation);
  return {
    kind: 'famynex-kiosk-preparation',
    version: pins.version,
    prepared: true,
    dedicatedAccountOnly: true,
    releaseReverified: true,
    coreDatabaseReady: true,
    browserProfilePreserved: true,
    credentialsCopied: false,
    loginChanged: false,
    servicesStarted: false,
    kioskEnrolled: false,
    hardwareAccepted: false
  };
}

async function main() {
  if (
    process.argv.length !== 2 ||
    process.platform !== 'linux' ||
    process.arch !== 'x64' ||
    process.getuid() !== 0 ||
    process.versions.node.split('.')[0] !== '22'
  )
    fail('HOST_OR_ARGUMENTS');
  const directory = `/opt/famynex/releases/${approval.sha256}/runtime/updater`;
  const load = async (name) => {
    const path = join(directory, name);
    const f = await protectedFile(path, '/', 0, 0o644, 1024 * 1024);
    await f.close();
    return import(pathToFileURL(path));
  };
  const helpers = Object.assign(
    {},
    ...(await Promise.all(
      [
        'linux-appliance-stage-review.mjs',
        'linux-appliance-plan.mjs',
        'linux-appliance-installed-state.mjs',
        'linux-appliance-systemd.mjs',
        'linux-appliance-wait-ready.mjs'
      ].map(load)
    ))
  );
  console.info(
    'Imzali kurulum ve Core kontrol ediliyor. Yalnizca kiosk oturum dosyalari hazirlanacak; mevcut oturum kapatilmayacak...'
  );
  console.info(JSON.stringify(await prepareKiosk({ helpers }), null, 2));
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  main().catch((error) => {
    console.error(
      error instanceof KioskPreparationError
        ? error.message
        : 'Kiosk preparation failed [REVIEW_REQUIRED]. Keep existing files and operation lock.'
    );
    process.exitCode = 1;
  });
