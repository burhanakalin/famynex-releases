// Prepare the dedicated kiosk files only; no login switch or enrollment.
import { spawn } from 'node:child_process';
import { createHash, createPublicKey } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readlink, realpath, rename, rmdir } from 'node:fs/promises';
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
export class KioskLoginError extends Error {
  constructor(code) {
    super(
      `Kiosk login configuration failed [${code}]. Do not reboot; keep the current session and operation lock for review.`
    );
    this.code = code;
  }
}
const fail = (code) => {
  throw new KioskLoginError(code);
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
      reject(new KioskLoginError('COMMAND'));
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (failed || !allowed.includes(code)) reject(new KioskLoginError('COMMAND'));
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

// LightDM prints its merged configuration on stderr on the target Mint build.
// The shell string is fixed: no arguments, filenames or environment are interpolated.
const showConfiguration = ['-c', 'exec /usr/sbin/lightdm --show-config 2>&1'];

export function seatSettings(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 65536 || text.includes('\0'))
    fail('LIGHTDM_CONFIG');
  let section = '',
    seen = false;
  const settings = {};
  for (const original of text.split(/\r?\n/)) {
    const line = original.trim().replace(/^[A-Z]\s+/, '');
    if (!line || /^[#;]/.test(line)) continue;
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      section = header[1];
      if (section.startsWith('Seat:') && section !== 'Seat:*') fail('LIGHTDM_SEAT');
      if (section === 'Seat:*') {
        if (seen) fail('LIGHTDM_SEAT');
        seen = true;
      }
      continue;
    }
    if (section !== 'Seat:*') continue;
    const entry = /^([\w-]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (!entry) continue;
    if (Object.hasOwn(settings, entry[1])) fail('LIGHTDM_DUPLICATE');
    settings[entry[1]] = entry[2];
  }
  if (!seen) fail('LIGHTDM_SEAT');
  return settings;
}
function expectedSeat(settings, username) {
  if (
    settings['autologin-user'] !== username ||
    settings['autologin-user-timeout'] !== '0' ||
    settings['user-session'] !== 'xfce' ||
    ![undefined, 'false'].includes(settings['autologin-guest']) ||
    ![undefined, 'xfce'].includes(settings['autologin-session']) ||
    ![undefined, 'lightdm-autologin'].includes(settings['pam-autologin-service']) ||
    ![undefined, 'false'].includes(settings['autologin-in-background'])
  )
    fail('LIGHTDM_POLICY');
}
export function configureLogin(text) {
  const settings = seatSettings(text);
  if (
    settings['autologin-user'] !== 'burhan' ||
    settings['autologin-user-timeout'] !== '0' ||
    ![undefined, 'false'].includes(settings['autologin-guest']) ||
    ![undefined, 'xfce'].includes(settings['autologin-session'])
  )
    fail('LIGHTDM_POLICY');
  const newline = text.includes('\r\n') ? '\r\n' : '\n';
  let inSeat = false,
    changed = false,
    session = false;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(lines[i]);
    if (header) inSeat = header[1] === 'Seat:*';
    if (!inSeat) continue;
    if (/^\s*autologin-user\s*=/.test(lines[i])) {
      lines[i] = lines[i].replace(/(=\s*)burhan\s*$/, '$1famynex');
      changed = true;
    }
    if (/^\s*autologin-session\s*=/.test(lines[i])) session = true;
  }
  if (!changed) fail('LIGHTDM_POLICY');
  if (!session) {
    const index = lines.findIndex((line) => /^\s*\[Seat:\*\]\s*$/.test(line));
    lines.splice(index + 1, 0, 'autologin-session=xfce');
  }
  return lines.join(newline);
}
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
async function boundedSession(file, size) {
  const bytes = Buffer.alloc(size + 1),
    { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
  if (bytesRead !== size || (await file.stat()).size !== size) fail('KIOSK_SESSION');
  return bytes.subarray(0, bytesRead);
}
async function readProtected(path, root, uid, mode) {
  const f = await protectedFile(path, root, uid, mode);
  try {
    return { bytes: await f.readFile(), info: await f.stat() };
  } finally {
    await f.close();
  }
}

export async function prepareLogin({
  root = '/',
  uid = process.getuid(),
  pins = approval,
  run = command,
  helpers
} = {}) {
  root = await realpath(root);
  const at = (path) => join(root, path),
    updater = at('var/lib/famynex-updater');
  const installation = at('opt/famynex'),
    release = join(installation, 'releases', pins.sha256);
  for (const directory of [installation, updater, release, at('etc/lightdm')])
    await protectedDirectory(directory, root, uid);
  const installed = await helpers.readInstalledState(join(updater, 'installed'));
  if (
    installed.version !== pins.version ||
    installed.sequence !== pins.sequence ||
    installed.sha256 !== pins.sha256 ||
    installed.sourceTree !== pins.sourceTree ||
    installed.schemaVersion !== pins.schema
  )
    fail('INSTALLED_STATE');
  const current = join(installation, 'current'),
    currentInfo = await lstat(current);
  if (
    !currentInfo.isSymbolicLink() ||
    currentInfo.uid !== uid ||
    (await readlink(current)) !== `releases/${pins.sha256}`
  )
    fail('CURRENT');
  const preparation = await json(join(updater, 'kiosk-preparation.json'), root, uid);
  if (
    preparation.formatVersion !== 1 ||
    preparation.version !== pins.version ||
    preparation.sha256 !== pins.sha256 ||
    preparation.loginChanged !== false ||
    preparation.enrolled !== false ||
    !Number.isInteger(preparation.accountUid) ||
    preparation.accountUid < 1 ||
    !Number.isInteger(preparation.accountGid) ||
    preparation.accountGid < 1
  )
    fail('KIOSK_PREPARATION');
  const passwd = (await run('/usr/bin/getent', ['passwd', 'famynex'])).stdout.split(':');
  if (
    passwd.length !== 7 ||
    passwd[0] !== 'famynex' ||
    passwd[2] !== String(preparation.accountUid) ||
    passwd[3] !== String(preparation.accountGid) ||
    passwd[5] !== '/var/lib/famynex' ||
    passwd[6] !== '/bin/bash'
  )
    fail('ACCOUNT');
  const definitions = helpers.runtimePlan({});
  const unit = definitions.userUnits['famynex-kiosk.service'].replace(
    '[Unit]\n',
    '[Unit]\nConditionUser=famynex\n'
  );
  const session = definitions.sessionFiles['famynex-kiosk.desktop'];
  const unitFile = await readProtected(
    at('etc/systemd/user/famynex-kiosk.service'),
    root,
    uid,
    0o644
  );
  if (
    hash(unitFile.bytes) !== hash(unit) ||
    preparation.unitSha256 !== hash(unit) ||
    preparation.sessionSha256 !== hash(session)
  )
    fail('KIOSK_UNIT');
  const home = at('var/lib/famynex');
  for (const path of [
    home,
    join(home, 'browser'),
    join(home, '.config'),
    join(home, '.config/autostart')
  ]) {
    const info = await lstat(path);
    if (
      !info.isDirectory() ||
      info.isSymbolicLink() ||
      info.uid !== preparation.accountUid ||
      info.gid !== preparation.accountGid ||
      (info.mode & 0o7777) !== 0o700 ||
      (await realpath(path)) !== path
    )
      fail('PROFILE');
  }
  // Reading a bounded file in the app-owned home does not grant the app root code execution.
  const file = await open(
    join(home, '.config/autostart/famynex-kiosk.desktop'),
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
  );
  try {
    const info = await file.stat();
    if (
      !info.isFile() ||
      info.nlink !== 1 ||
      info.uid !== preparation.accountUid ||
      info.gid !== preparation.accountGid ||
      (info.mode & 0o7777) !== 0o644 ||
      info.size !== Buffer.byteLength(session) ||
      hash(await boundedSession(file, info.size)) !== hash(session)
    )
      fail('KIOSK_SESSION');
  } finally {
    await file.close();
  }
  const xfce = await readProtected(at('usr/share/xsessions/xfce.desktop'), root, uid, 0o644);
  if (!/^Exec=\S[^\r\n]*xfce[^\r\n]*$/m.test(xfce.bytes.toString('utf8'))) fail('XFCE');
  const core = await helpers.serviceState('famynex-core.service');
  if (
    core.state !== 'active' ||
    core.pid < 1 ||
    (await realpath(at(`proc/${core.pid}/cwd`))) !== join(release, 'apps/web') ||
    !(await helpers.waitForCore({ deadlineMs: 85000 }))
  )
    fail('CORE_HEALTH');
  const path = at('etc/lightdm/lightdm.conf');
  const original = await readProtected(path, root, uid, 0o644);
  // Refuse non-UTF8 rather than rewriting unrecognized bytes.
  const text = new TextDecoder('utf-8', { fatal: true }).decode(original.bytes),
    replacement = configureLogin(text);
  expectedSeat(seatSettings((await run('/bin/sh', showConfiguration)).stdout), 'burhan');
  const backup = join(updater, 'lightdm-before-kiosk.conf'),
    record = join(updater, 'kiosk-login.json');
  for (const destination of [backup, record]) await absent(destination);
  const lock = join(installation, '.famynex-install.lock');
  try {
    await mkdir(lock, { mode: 0o700 });
  } catch (e) {
    if (e.code === 'EEXIST') fail('BUSY');
    throw e;
  }
  await sync(installation);
  await write(backup, original.bytes);
  await write(
    join(updater, 'kiosk-login-intent.json'),
    JSON.stringify({
      formatVersion: 1,
      phase: 'prepared',
      previousConfigSha256: hash(original.bytes),
      configuredSha256: hash(replacement)
    })
  );
  const latest = await readProtected(path, root, uid, 0o644);
  if (
    latest.info.ino !== original.info.ino ||
    latest.info.dev !== original.info.dev ||
    hash(latest.bytes) !== hash(original.bytes)
  )
    fail('CONFIG_CHANGED');
  expectedSeat(seatSettings((await run('/bin/sh', showConfiguration)).stdout), 'burhan');
  const latestCore = await helpers.serviceState('famynex-core.service');
  if (
    latestCore.state !== 'active' ||
    latestCore.pid !== core.pid ||
    (await readlink(current)) !== `releases/${pins.sha256}`
  )
    fail('CORE_CHANGED');
  // Same /var and /etc device is not assumed: stage the replacement beside the
  // original config for an atomic rename. Every path here has root-only writers.
  const temporary = at('etc/lightdm/.famynex-kiosk.pending');
  await write(temporary, replacement, 0o644);
  const finalCheck = await readProtected(path, root, uid, 0o644);
  if (hash(finalCheck.bytes) !== hash(original.bytes) || finalCheck.info.ino !== original.info.ino)
    fail('CONFIG_CHANGED');
  await rename(temporary, path);
  await sync(dirname(path));
  const actual = await readProtected(path, root, uid, 0o644);
  if (hash(actual.bytes) !== hash(replacement)) fail('CONFIG_VERIFY');
  expectedSeat(seatSettings((await run('/bin/sh', showConfiguration)).stdout), 'famynex');
  await write(
    record,
    JSON.stringify({
      formatVersion: 1,
      version: pins.version,
      sha256: pins.sha256,
      previousConfigSha256: hash(original.bytes),
      configuredSha256: hash(actual.bytes),
      previousAutologinUser: 'burhan',
      autologinUser: 'famynex',
      session: 'xfce',
      rebootRequired: true,
      enrolled: false
    })
  );
  await rmdir(lock);
  await sync(installation);
  return {
    kind: 'famynex-kiosk-login-configuration',
    configured: true,
    autologinUser: 'famynex',
    session: 'xfce',
    previousConfigurationBackedUp: true,
    effectiveConfigurationVerified: true,
    currentSessionClosed: false,
    rebootRequired: true,
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
    const path = join(directory, name),
      f = await protectedFile(path, '/', 0, 0o644, 1024 * 1024);
    await f.close();
    return import(pathToFileURL(path));
  };
  const helpers = Object.assign(
    {},
    ...(await Promise.all(
      [
        'linux-appliance-plan.mjs',
        'linux-appliance-installed-state.mjs',
        'linux-appliance-systemd.mjs',
        'linux-appliance-wait-ready.mjs'
      ].map(load)
    ))
  );
  console.info(
    'Kiosk dosyalari ve Core dogrulaniyor. Giris ayari yedeklenecek; mevcut oturum kapatilmayacak...'
  );
  console.info(JSON.stringify(await prepareLogin({ helpers }), null, 2));
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  main().catch((error) => {
    console.error(
      error instanceof KioskLoginError
        ? error.message
        : 'Kiosk login configuration failed [REVIEW_REQUIRED]. Do not reboot; retain current session and operation lock.'
    );
    process.exitCode = 1;
  });
