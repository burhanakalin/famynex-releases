// Prepare the dedicated kiosk files only; no login switch or enrollment.
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
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
export class EnrollmentError extends Error {
  constructor(code) {
    super(
      `Physical display enrollment failed [${code}]. Keep the saved home and operation lock for review.`
    );
    this.code = code;
  }
}
const fail = (code) => {
  throw new EnrollmentError(code);
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
      reject(new EnrollmentError('COMMAND'));
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (failed || !allowed.includes(code)) reject(new EnrollmentError('COMMAND'));
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

const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const kioskUnit = 'famynex-kiosk.service',
  browserUnit = 'famynex-display-enrollment.service';
export function properties(text, names) {
  const values = {};
  for (const line of text.split('\n')) {
    const match = /^([A-Za-z]+)=(.*)$/.exec(line);
    if (!match || !names.includes(match[1]) || Object.hasOwn(values, match[1]))
      fail('SESSION_PROPERTIES');
    values[match[1]] = match[2];
  }
  if (Object.keys(values).length !== names.length) fail('SESSION_PROPERTIES');
  return values;
}
export function bootstrapAddress(line) {
  const match =
    /^Open http:\/\/localhost:([1-9]\d{0,4})\/ on this device within 60 seconds\. This one-use address contains no credential\.$/.exec(
      line
    );
  if (!match || Number(match[1]) > 65535 || Number(match[1]) === 3000) fail('LAUNCHER_OUTPUT');
  return `http://localhost:${match[1]}/`;
}
export function launcherArguments(release, unit) {
  return [
    '--quiet',
    '--wait',
    '--pipe',
    '--collect',
    '--service-type=exec',
    `--unit=${unit}`,
    '--property=User=famynex',
    '--property=Group=famynex',
    `--property=WorkingDirectory=${release}`,
    '--property=EnvironmentFile=/etc/famynex/core.env',
    '--property=Environment=NODE_ENV=production FAMYNEX_RUNTIME_ROLE=local-core PGAPPNAME=famynex-display-enroll',
    '--property=RuntimeMaxSec=90',
    '--property=TimeoutStopSec=5',
    '--property=KillMode=control-group',
    '--property=NoNewPrivileges=true',
    '--property=ProtectSystem=strict',
    '--property=ProtectHome=true',
    '--property=PrivateTmp=true',
    '--property=StandardError=null',
    '/usr/bin/node',
    join(release, 'runtime/display-launcher.mjs')
  ];
}
export function startBootstrap({
  release,
  unit,
  timeoutMs = 95000,
  executable = '/usr/bin/systemd-run',
  args = launcherArguments(release, unit)
}) {
  const child = spawn(executable, args, {
    env: minimal,
    shell: false,
    detached: true,
    stdio: ['ignore', 'pipe', 'ignore']
  });
  let buffer = '',
    got = false,
    closed = false,
    rejectReady,
    resolveReady,
    rejectFinished,
    resolveFinished,
    failed = false;
  const ready = new Promise((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  const finished = new Promise((resolve, reject) => {
    resolveFinished = resolve;
    rejectFinished = reject;
  });
  // A failure can arrive while the coordinator is still awaiting the first line.
  finished.catch(() => {});
  const stop = () => {
    try {
      if (!closed && child.pid) process.kill(-child.pid, 'SIGKILL');
    } catch {}
  };
  const reject = () => {
    failed = true;
    rejectReady(new EnrollmentError('LAUNCHER'));
    rejectFinished(new EnrollmentError('LAUNCHER'));
    stop();
  };
  const timer = setTimeout(reject, timeoutMs);
  child.stdout.on('data', (chunk) => {
    if (failed) return;
    if (got || Buffer.byteLength(buffer) + chunk.length > 1024) {
      reject();
      return;
    }
    buffer += chunk.toString('utf8');
    if (buffer.includes('\n')) {
      const lines = buffer.split('\n');
      if (lines.length !== 2 || lines[1] !== '' || lines[0].includes('\r')) {
        reject();
        return;
      }
      try {
        const address = bootstrapAddress(lines[0]);
        got = true;
        resolveReady(address);
      } catch {
        reject();
      }
    }
  });
  child.once('error', reject);
  child.once('close', (code) => {
    closed = true;
    clearTimeout(timer);
    if (code !== 0 || !got || failed) reject();
    else resolveFinished();
  });
  return {
    ready,
    finished,
    stop: async () => {
      if (!closed) stop();
      await finished.catch(() => {});
    }
  };
}
async function checkInstalled({ root, uid, pins, helpers }) {
  const at = (path) => join(root, path),
    updater = at('var/lib/famynex-updater'),
    installation = at('opt/famynex'),
    release = join(installation, 'releases', pins.sha256);
  for (const directory of [updater, installation, release])
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
  const current = await lstat(join(installation, 'current'));
  if (
    !current.isSymbolicLink() ||
    current.uid !== uid ||
    (await readlink(join(installation, 'current'))) !== `releases/${pins.sha256}`
  )
    fail('CURRENT');
  const login = await json(join(updater, 'kiosk-login.json'), root, uid),
    prepared = await json(join(updater, 'kiosk-preparation.json'), root, uid);
  if (
    login.formatVersion !== 1 ||
    login.version !== pins.version ||
    login.sha256 !== pins.sha256 ||
    login.autologinUser !== 'famynex' ||
    login.session !== 'xfce' ||
    prepared.version !== pins.version ||
    prepared.sha256 !== pins.sha256
  )
    fail('PREPARATION');
  const numeric = /^[1-9]\d{0,8}$/;
  if (!numeric.test(String(prepared.accountUid)) || !numeric.test(String(prepared.accountGid)))
    fail('ACCOUNT');
  const home = at('var/lib/famynex');
  for (const path of [home, join(home, 'browser')]) {
    const info = await lstat(path);
    if (
      !info.isDirectory() ||
      info.isSymbolicLink() ||
      info.uid !== prepared.accountUid ||
      info.gid !== prepared.accountGid ||
      (info.mode & 0o7777) !== 0o700 ||
      (await realpath(path)) !== path
    )
      fail('PROFILE');
  }
  for (const path of [at('etc/famynex/core.env'), join(release, 'runtime/display-launcher.mjs')]) {
    const f = await protectedFile(
      path,
      root,
      uid,
      path.endsWith('core.env') ? 0o600 : 0o644,
      32 * 1024 * 1024
    );
    await f.close();
  }
  const core = await helpers.serviceState('famynex-core.service');
  if (
    core.state !== 'active' ||
    core.pid < 1 ||
    (await realpath(at(`proc/${core.pid}/cwd`))) !== join(release, 'apps/web') ||
    !(await helpers.waitForCore({ deadlineMs: 85000 }))
  )
    fail('CORE_HEALTH');
  return {
    root,
    uid,
    pins,
    helpers,
    updater,
    installation,
    release,
    home,
    accountUid: prepared.accountUid,
    accountGid: prepared.accountGid
  };
}
export async function prepareEnrollment({
  root = '/',
  uid = process.getuid(),
  pins = approval,
  helpers,
  sourcePath
} = {}) {
  root = await realpath(root);
  const context = await checkInstalled({ root, uid, pins, helpers });
  const source = await protectedFile(sourcePath, root, uid, 0o600, 65536);
  let bytes;
  try {
    bytes = await source.readFile();
  } finally {
    await source.close();
  }
  const destination = join(context.updater, 'enroll-display-0.1.1.mjs');
  await absent(destination);
  const lock = join(context.installation, '.famynex-install.lock');
  try {
    await mkdir(lock, { mode: 0o700 });
  } catch (e) {
    if (e.code === 'EEXIST') fail('BUSY');
    throw e;
  }
  await sync(context.installation);
  await write(destination, bytes);
  await write(
    join(context.updater, 'enrollment-tool.json'),
    JSON.stringify({
      formatVersion: 1,
      version: pins.version,
      sha256: pins.sha256,
      toolSha256: digest(bytes)
    })
  );
  await rmdir(lock);
  await sync(context.installation);
  return {
    kind: 'famynex-physical-enrollment-preparation',
    prepared: true,
    version: pins.version,
    coreDatabaseReady: true,
    bootstrapIssued: false,
    browserStarted: false,
    currentSessionClosed: false,
    rebootReady: true,
    kioskEnrolled: false,
    hardwareAccepted: false
  };
}
export async function enrollDisplay({
  root = '/',
  uid = process.getuid(),
  pins = approval,
  helpers,
  run = command,
  consoleProof,
  launch = startBootstrap
} = {}) {
  root = await realpath(root);
  // Only a real physical VT with a nonremote seat0 login can invoke this operation.
  // Fixture seams are trusted in-process only and are never CLI/environment options.
  const tty = await (
    consoleProof ?? (async () => (process.stdin.isTTY ? realpath('/proc/self/fd/0') : ''))
  )();
  if (!/^\/dev\/tty[1-9]\d?$/.test(tty)) fail('PHYSICAL_CONSOLE');
  const physical = properties(
    (
      await run('/usr/bin/loginctl', [
        'show-session',
        'self',
        '--all',
        '--property=Remote',
        '--property=Seat',
        '--property=Type'
      ])
    ).stdout,
    ['Remote', 'Seat', 'Type']
  );
  if (physical.Remote !== 'no' || physical.Seat !== 'seat0' || physical.Type !== 'tty')
    fail('PHYSICAL_CONSOLE');
  const c = await checkInstalled({ root, uid, pins, helpers });
  const tool = await json(join(c.updater, 'enrollment-tool.json'), root, uid);
  const self = await protectedFile(
    join(c.updater, 'enroll-display-0.1.1.mjs'),
    root,
    uid,
    0o600,
    65536
  );
  try {
    if (
      tool.formatVersion !== 1 ||
      tool.version !== pins.version ||
      tool.sha256 !== pins.sha256 ||
      digest(await self.readFile()) !== tool.toolSha256
    )
      fail('TOOL');
  } finally {
    await self.close();
  }
  const user = properties(
    (
      await run('/usr/bin/loginctl', [
        'show-user',
        'famynex',
        '--all',
        '--property=UID',
        '--property=Sessions'
      ])
    ).stdout,
    ['UID', 'Sessions']
  );
  if (user.UID !== String(c.accountUid)) fail('ACCOUNT');
  const sessions = user.Sessions.split(' ');
  if (
    !sessions.length ||
    sessions.length > 10 ||
    sessions.some((id) => !/^\d{1,10}$|^c\d{1,10}$/.test(id))
  )
    fail('GRAPHICAL_SESSION');
  const graphical = [];
  for (const id of sessions) {
    const s = properties(
      (
        await run('/usr/bin/loginctl', [
          'show-session',
          id,
          '--all',
          '--property=Remote',
          '--property=Seat',
          '--property=Type',
          '--property=Name',
          '--property=User',
          '--property=Class',
          '--property=State',
          '--property=Display'
        ])
      ).stdout,
      ['Remote', 'Seat', 'Type', 'Name', 'User', 'Class', 'State', 'Display']
    );
    if (
      s.Remote === 'no' &&
      s.Seat === 'seat0' &&
      s.Type === 'x11' &&
      s.Name === 'famynex' &&
      s.User === String(c.accountUid) &&
      s.Class === 'user' &&
      ['active', 'online'].includes(s.State) &&
      /^:\d{1,3}(?:\.\d)?$/.test(s.Display)
    )
      graphical.push({ id, ...s });
  }
  if (graphical.length !== 1) fail('GRAPHICAL_SESSION');
  const gui = graphical[0];
  const runtime = `/run/user/${c.accountUid}`,
    bus = `unix:path=${runtime}/bus`;
  const userRun = (program, args) =>
    run(
      '/usr/sbin/runuser',
      [
        '-u',
        'famynex',
        '--',
        '/usr/bin/env',
        '-i',
        `PATH=${minimal.PATH}`,
        'LANG=C.UTF-8',
        `XDG_RUNTIME_DIR=${runtime}`,
        `DBUS_SESSION_BUS_ADDRESS=${bus}`,
        program,
        ...args
      ],
      { timeoutMs: 30000 }
    );
  const environment = (await userRun('/usr/bin/systemctl', ['--user', 'show-environment'])).stdout;
  const values = {};
  for (const line of environment.split('\n')) {
    const pair = /^(DISPLAY|XAUTHORITY)=(.*)$/.exec(line);
    if (pair) {
      if (Object.hasOwn(values, pair[1])) fail('GRAPHICAL_ENVIRONMENT');
      values[pair[1]] = pair[2];
    }
  }
  if (
    values.DISPLAY !== gui.Display ||
    !values.XAUTHORITY?.startsWith('/') ||
    values.XAUTHORITY.length > 512 ||
    /[\x00-\x1f\x7f]/.test(values.XAUTHORITY)
  )
    fail('GRAPHICAL_ENVIRONMENT');
  const browserState = (
    await userRun('/usr/bin/systemctl', ['--user', 'show', browserUnit, '--property=LoadState'])
  ).stdout;
  if (browserState !== 'LoadState=not-found') fail('EXISTING_ENROLLMENT_BROWSER');
  const lock = join(c.installation, '.famynex-install.lock');
  try {
    await mkdir(lock, { mode: 0o700 });
  } catch (e) {
    if (e.code === 'EEXIST') fail('BUSY');
    throw e;
  }
  await sync(c.installation);
  const attempt = join(c.updater, `display-enrollment-${randomUUID()}`);
  await mkdir(attempt, { mode: 0o700 });
  await write(
    join(attempt, 'intent.json'),
    JSON.stringify({
      formatVersion: 1,
      version: pins.version,
      sha256: pins.sha256,
      physicalConsole: true,
      displayEnrollmentConfirmed: false
    })
  );
  let bootstrap,
    browserAttempted = false;
  const launcherUnit = `famynex-physical-launcher-${randomUUID()}.service`;
  try {
    await userRun('/usr/bin/systemctl', ['--user', 'stop', kioskUnit]);
    const stopped = properties(
      (
        await userRun('/usr/bin/systemctl', [
          '--user',
          'show',
          kioskUnit,
          '--property=ActiveState',
          '--property=MainPID'
        ])
      ).stdout,
      ['ActiveState', 'MainPID']
    );
    if (stopped.ActiveState !== 'inactive' || stopped.MainPID !== '0') fail('KIOSK_NOT_STOPPED');
    for (const name of ['SingletonLock', 'SingletonSocket'])
      await absent(join(c.home, 'browser', name));
    bootstrap = launch({ release: c.release, unit: launcherUnit });
    const address = await bootstrap.ready;
    const browserEnv = [
      '/usr/bin/env',
      '-i',
      'PATH=/usr/bin:/bin',
      'LANG=C.UTF-8',
      'HOME=/var/lib/famynex',
      'USER=famynex',
      'LOGNAME=famynex',
      `DISPLAY=${values.DISPLAY}`,
      `XAUTHORITY=${values.XAUTHORITY}`,
      `XDG_RUNTIME_DIR=${runtime}`,
      `DBUS_SESSION_BUS_ADDRESS=${bus}`,
      'XDG_SESSION_TYPE=x11',
      'XDG_CURRENT_DESKTOP=XFCE'
    ];
    browserAttempted = true;
    await userRun('/usr/bin/systemd-run', [
      '--user',
      '--quiet',
      '--collect',
      '--service-type=exec',
      `--unit=${browserUnit}`,
      '--property=Restart=no',
      '--property=TimeoutStopSec=10',
      '--property=KillMode=control-group',
      '--property=UMask=0077',
      '--property=StandardOutput=null',
      '--property=StandardError=null',
      '--property=ExecStartPre=/usr/bin/systemctl --user reset-failed famynex-kiosk.service',
      '--property=ExecStopPost=/usr/bin/systemctl --user start famynex-kiosk.service',
      ...browserEnv,
      '/usr/bin/chromium',
      '--user-data-dir=/var/lib/famynex/browser',
      '--no-first-run',
      '--no-default-browser-check',
      address
    ]);
    await run('/usr/bin/loginctl', ['activate', gui.id]);
    await bootstrap.finished;
    await write(
      join(attempt, 'exchange.json'),
      JSON.stringify({
        formatVersion: 1,
        bootstrapExchangeCompleted: true,
        displayEnrollmentConfirmed: false,
        browserCloseResumesKiosk: true
      })
    );
    await rmdir(lock);
    await sync(c.installation);
    return {
      kind: 'famynex-physical-display-handoff',
      bootstrapExchangeCompleted: true,
      dedicatedProfileOpened: true,
      graphicalSessionActivated: true,
      browserCloseResumesKiosk: true,
      displayEnrollmentConfirmed: false,
      keysRegenerated: false,
      hardwareAccepted: false
    };
  } catch (error) {
    await run('/usr/bin/systemctl', ['stop', launcherUnit], { timeoutMs: 15000 }).catch(() => {});
    await bootstrap?.stop();
    if (browserAttempted)
      await userRun('/usr/bin/systemctl', ['--user', 'stop', browserUnit]).catch(() => {});
    // No reissue, cookie copy, profile reset or automatic crash-lock clearing.
    if (error instanceof EnrollmentError) throw error;
    fail('HANDOFF');
  }
}
async function main() {
  if (
    ![2, 3].includes(process.argv.length) ||
    (process.argv.length === 3 && process.argv[2] !== '--prepare') ||
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
        'linux-appliance-installed-state.mjs',
        'linux-appliance-systemd.mjs',
        'linux-appliance-wait-ready.mjs'
      ].map(load)
    ))
  );
  const result =
    process.argv[2] === '--prepare'
      ? await prepareEnrollment({ helpers, sourcePath: resolve(process.argv[1]) })
      : await enrollDisplay({ helpers });
  console.info(JSON.stringify(result, null, 2));
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  main().catch((error) => {
    console.error(
      error instanceof EnrollmentError
        ? error.message
        : 'Physical display enrollment failed [REVIEW_REQUIRED]. Keep the saved home and operation lock.'
    );
    process.exitCode = 1;
  });
