// Supervised first Core/calendar installation. No update API or CLI overrides.
import { spawn } from 'node:child_process';
import { createHash, createPublicKey, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import {
  chmod,
  chown,
  lstat,
  mkdir,
  open,
  readdir,
  readlink,
  realpath,
  rmdir,
  symlink
} from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
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
export const migrations = Object.freeze([
  '0001_create_schema_migrations.sql',
  '0002_create_core_family_profile_schema.sql',
  '0003_create_calendar_events.sql',
  '0004_create_tasks.sql',
  '0005_create_external_calendar_accounts.sql',
  '0006_create_external_calendar_event_mappings.sql',
  '0007_create_external_calendar_sync_runs.sql',
  '0008_create_external_calendar_sources.sql',
  '0009_add_external_calendar_writeback_state.sql',
  '0010_create_user_identity_profile_links.sql',
  '0011_create_family_membership_permissions.sql',
  '0012_add_better_auth.sql',
  '0013_add_family_profile_status.sql',
  '0014_create_routine_persistence.sql',
  '0015_create_meal_plan_persistence.sql',
  '0016_create_shopping_list_persistence.sql',
  '0017_create_remote_bridge_persistence.sql',
  '0018_create_local_installation.sql',
  '0019_calendar_display_privacy.sql',
  '0020_task_date_ranges.sql',
  '0021_create_local_parent_access.sql',
  '0022_create_parent_invitations.sql',
  '0023_local_device_lifecycle.sql',
  '0024_remote_relink_attempts.sql',
  '0025_local_device_preferences.sql',
  '0026_display_enrollment.sql'
]);
const units = ['famynex-core.service', 'famynex-calendar.service'];
const minimal = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
export class InitialCoreError extends Error {
  constructor(code) {
    super(
      `Initial Core installation failed [${code}]. Keep the saved home and operation lock for review.`
    );
    this.code = code;
  }
}
const fail = (code) => {
  throw new InitialCoreError(code);
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
      reject(new InitialCoreError('COMMAND'));
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (failed || !allowed.includes(code)) reject(new InitialCoreError('COMMAND'));
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
export function identity(value) {
  if (
    !value ||
    value.configured !== true ||
    typeof value.installationId !== 'string' ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value.installationId) ||
    typeof value.householdId !== 'string' ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(value.householdId) ||
    JSON.stringify(value.migrations) !== JSON.stringify(migrations)
  )
    fail('HOUSEHOLD_OR_SCHEMA');
  return {
    installationId: value.installationId,
    householdId: value.householdId,
    migrations: [...migrations]
  };
}
const peerSQL = `SELECT json_build_object('installationId',id::text,'householdId',household_id,
'configured',state->>'kind'='configured' AND state->>'householdId'=household_id,
'migrations',(SELECT json_agg(name ORDER BY name) FROM public.schema_migrations))
FROM public.local_installation WHERE singleton=true;`;
export async function peerIdentity(run = command) {
  const result = await run(
    '/usr/sbin/runuser',
    [
      '-u',
      'postgres',
      '--',
      '/usr/bin/psql',
      '-X',
      '--no-password',
      '--host=/var/run/postgresql',
      '--port=5432',
      '--dbname=famynex',
      '-At',
      '--set=ON_ERROR_STOP=1',
      '-c',
      peerSQL
    ],
    {
      env: {
        ...minimal,
        PGAPPNAME: 'famynex-install-peer',
        PGPASSFILE: '/dev/null',
        PGSERVICEFILE: '/dev/null',
        PGOPTIONS:
          '-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000'
      }
    }
  );
  try {
    return identity(JSON.parse(result.stdout));
  } catch {
    fail('HOUSEHOLD_OR_SCHEMA');
  }
}

// This worker receives Core credentials ONLY through systemd EnvironmentFile.
// Its code/input/result files live in a root-private attempt directory.
export const workerCode = `
import { readFile, open } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const directory = fileURLToPath(new URL('./', import.meta.url));
try {
  const config = JSON.parse(await readFile(join(directory, 'worker-input.json'), 'utf8'));
  const backup = await import(pathToFileURL(join(config.helpers, 'linux-appliance-backup.mjs')));
  const phase = process.argv[2];
  if (!['backup', 'before-start', 'after-health'].includes(phase)) throw Error();
  const connection = backup.databaseEnvironment(process.env.DATABASE_URL);
  if (connection.PGDATABASE !== 'famynex' || connection.PGPORT !== '5432') throw Error();
  const options = { databaseUrl: process.env.DATABASE_URL, expected: config.expected, parent: config.backups };
  const calendarEnabled = process.env.CALENDAR_BACKGROUND_SYNC_ENABLED === 'true';
  await backup.reviewDatabase({ ...options, requireQuiescent: phase !== 'after-health' });
  let result;
  if (phase === 'backup') result = await backup.backupDatabase(options);
  else {
    const recorded = JSON.parse(await readFile(join(directory, 'database-backup.json'), 'utf8'));
    const reviewed = await backup.reviewBackup({ parent: config.backups, name: recorded.name, expected: config.expected });
    if (reviewed.sha256 !== recorded.sha256 || reviewed.bytes !== recorded.bytes) throw Object.assign(Error(), { code: 'BACKUP_MISMATCH' });
    result = { verified: true, calendarEnabled };
  }
  if (phase === 'backup') result = { name: result.backupDirectory.split('/').at(-1),
    sha256: result.sha256, bytes: result.bytes, archiveDecoded: result.archiveDecoded, restoreDrillVerified: false, calendarEnabled };
  const f = await open(join(directory, 'database-' + phase + '.json'), 'wx', 0o600);
  try { await f.writeFile(JSON.stringify(result)); await f.sync(); } finally { await f.close(); }
  const parent = await open(directory, 'r');
  try { await parent.sync(); } finally { await parent.close(); }
} catch (error) {
  const safe = new Set(['CONNECTION', 'IDENTITY', 'IDENTITY_MISMATCH', 'PROBE', 'VERSION',
    'PARENT', 'BUSY', 'DISK', 'DUMP_SIZE', 'DUMP', 'TOOL', 'SOURCE_CHANGED',
    'DATABASE_WRITERS_ACTIVE', 'BACKUP_FILE', 'DIGEST', 'BACKUP_MISMATCH',
    'ENOENT', 'EACCES', 'ENOSPC', 'EROFS', 'IO']);
  const code = safe.has(error.code) ? error.code : 'WORKER';
  try {
    const f = await open(join(directory, 'database-error.json'), 'wx', 0o600);
    try { await f.writeFile(JSON.stringify({ code })); await f.sync(); } finally { await f.close(); }
  } catch {}
  process.exitCode = 1;
}
`;

export async function databasePhase(phase, context, run = command) {
  const unit = `famynex-initial-database-${randomUUID()}`;
  try {
    await run(
      '/usr/bin/systemd-run',
      [
        '--quiet',
        '--wait',
        '--collect',
        '--service-type=exec',
        `--unit=${unit}`,
        `--property=EnvironmentFile=${context.coreEnvironment}`,
        '--property=RuntimeMaxSec=600',
        '--property=TimeoutStopSec=5',
        '--property=KillMode=control-group',
        '--property=NoNewPrivileges=true',
        '--property=ProtectSystem=strict',
        '--property=ProtectHome=true',
        '--property=PrivateTmp=true',
        `--property=ReadWritePaths=${context.updater}`,
        '--property=StandardOutput=null',
        '--property=StandardError=null',
        '/usr/bin/node',
        join(context.attempt, 'database-worker.mjs'),
        phase
      ],
      { timeoutMs: 650000 }
    );
  } catch {
    // Killing systemd-run's client does not terminate a transient service.
    // Explicitly stop its known process group through the service manager too.
    await run('/usr/bin/systemctl', ['stop', unit], { timeoutMs: 30000 }).catch(() => {});
    let detail;
    try {
      const error = await json(
        join(context.attempt, 'database-error.json'),
        context.root,
        context.uid
      );
      if (/^[A-Z_]{1,48}$/.test(error.code)) detail = error.code;
    } catch {}
    fail(detail ? `DATABASE_${detail}` : 'DATABASE_CHECK_OR_BACKUP');
  }
  return json(join(context.attempt, `database-${phase}.json`), context.root, context.uid);
}

export async function portAvailable(root = '/') {
  for (const [name, optional] of [
    ['tcp', false],
    ['tcp6', true]
  ]) {
    let f;
    try {
      f = await open(
        join(root, 'proc/net', name),
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
      );
      const data = Buffer.alloc(8 * 1024 * 1024 + 1);
      let size = 0;
      while (size < data.length) {
        const part = await f.read(data, size, data.length - size, null);
        if (!part.bytesRead) break;
        size += part.bytesRead;
      }
      if (!size || size >= data.length) fail('PORT_INSPECTION');
      const lines = data.subarray(0, size).toString().trim().split('\n');
      if (
        !/^\s*sl\s+local_address\s+(?:rem_address|remote_address)\s+st\s/.test(lines.shift() ?? '')
      )
        fail('PORT_INSPECTION');
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        const address =
          name === 'tcp' ? /^[a-f0-9]{8}:[a-f0-9]{4}$/i : /^[a-f0-9]{32}:[a-f0-9]{4}$/i;
        if (parts.length < 10 || !address.test(parts[1]) || !/^[a-f0-9]{2}$/i.test(parts[3]))
          fail('PORT_INSPECTION');
        if (parts[3].toUpperCase() === '0A' && parts[1].split(':')[1].toUpperCase() === '0BB8')
          return false;
      }
    } catch (e) {
      if (!(optional && e.code === 'ENOENT')) throw e;
    } finally {
      await f?.close();
    }
  }
  return true;
}

export async function installInitialCore({
  root = '/',
  helpers,
  pins = approval,
  run = command,
  database = databasePhase,
  peer = peerIdentity,
  available = portAvailable,
  processRoot,
  fetchHealth,
  recoverDisabledCalendar = false,
  uid = process.getuid()
} = {}) {
  // All seams are trusted in-process fixtures. The CLI accepts NO overrides.
  root = await realpath(root);
  const at = (path) => join(root, path);
  const installation = at('opt/famynex'),
    updater = at('var/lib/famynex-updater');
  const release = join(installation, 'releases', pins.sha256),
    helperDirectory = join(release, 'runtime/updater');
  const coreEnvironment = at('etc/famynex/core.env');
  await protectedDirectory(installation, root, uid);
  await protectedDirectory(updater, root, uid);
  await protectedDirectory(release, root, uid);
  for (const [path, mode] of [
    [coreEnvironment, 0o600],
    [at('var/lib/famynex-policy/setup-policy.json'), 0o644]
  ]) {
    const f = await protectedFile(path, root, uid, mode, 262144);
    await f.close();
  }
  const record = await json(join(updater, 'initial-preparation.json'), root, uid);
  if (
    record.kind !== 'famynex-initial-release-preparation' ||
    record.rootOwned !== true ||
    record.independentlyRechecked !== true ||
    record.installed !== false ||
    record.activated !== false ||
    record.releaseDirectory !== release ||
    ['version', 'sequence', 'sourceCommit', 'sourceTree', 'sha256'].some(
      (key) => record[key] !== pins[key]
    ) ||
    dirname(record.stagingDirectory ?? '') !== join(updater, 'staging') ||
    !/^\.famynex-stage-[A-Za-z0-9_-]{6,32}$/.test(basename(record.stagingDirectory))
  )
    fail('PREPARATION');
  const trust = await json(join(updater, 'initial-trust.json'), root, uid);
  if (
    trust.formatVersion !== 1 ||
    trust.keys?.length !== 1 ||
    trust.keys[0].id !== pins.keyId ||
    trust.keys[0].status !== 'active'
  )
    fail('TRUST');
  const fingerprint = createHash('sha256')
    .update(createPublicKey(trust.keys[0].publicKey).export({ type: 'spki', format: 'der' }))
    .digest('hex');
  if (fingerprint !== pins.fingerprint) fail('TRUST');
  const freshPaths = async () => {
    for (const path of [
      'var/lib/famynex',
      'var/cache/famynex',
      'opt/famynex/current',
      'var/lib/famynex-updater/installed',
      'var/lib/famynex-updater/initial-core.json'
    ]) {
      await protectedDirectory(dirname(at(path)), root, uid);
      await absent(at(path));
    }
  };
  const lock = join(installation, '.famynex-install.lock');
  let recoveryInput, recoveryBackup, originalJournal, recoveryClaim;
  const definitions = helpers.runtimePlan({}).units;
  const numeric = async (flag) => {
    const s = (await run('/usr/bin/id', [flag, 'famynex'])).stdout;
    if (!/^[1-9]\d{0,8}$/.test(s)) fail('ACCOUNT');
    return Number(s);
  };
  if (recoverDisabledCalendar) {
    originalJournal = await json(join(updater, 'initial-core.json'), root, uid);
    if (
      Object.keys(originalJournal).sort().join(',') !== 'formatVersion,phase,sha256,version' ||
      originalJournal.formatVersion !== 1 ||
      originalJournal.phase !== 'starting' ||
      originalJournal.version !== pins.version ||
      originalJournal.sha256 !== pins.sha256
    )
      fail('RECOVERY_PHASE');
    await absent(join(updater, 'installed'));
    await protectedDirectory(lock, root, uid);
    if (((await lstat(lock)).mode & 0o7777) !== 0o700 || (await readdir(lock)).length)
      fail('RECOVERY_LOCK');
    const current = await lstat(join(installation, 'current'));
    if (
      !current.isSymbolicLink() ||
      current.uid !== uid ||
      (await readlink(join(installation, 'current'))) !== `releases/${pins.sha256}`
    )
      fail('CURRENT');
    const user = (await run('/usr/bin/getent', ['passwd', 'famynex'])).stdout.split(':');
    const group = (await run('/usr/bin/getent', ['group', 'famynex'])).stdout.split(':');
    const accountUid = await numeric('-u'),
      accountGid = await numeric('-g');
    if (
      user.length !== 7 ||
      user[0] !== 'famynex' ||
      user[2] !== String(accountUid) ||
      user[3] !== String(accountGid) ||
      user[5] !== '/var/lib/famynex' ||
      user[6] !== '/bin/bash' ||
      group.length !== 4 ||
      group[0] !== 'famynex' ||
      group[2] !== String(accountGid) ||
      group[3] !== ''
    )
      fail('RECOVERY_ACCOUNT');
    for (const name of ['var/lib/famynex', 'var/cache/famynex', 'var/lib/famynex/browser']) {
      const path = at(name),
        info = await lstat(path);
      if (
        !info.isDirectory() ||
        info.isSymbolicLink() ||
        info.uid !== accountUid ||
        info.gid !== accountGid ||
        (info.mode & 0o7777) !== 0o700 ||
        (await realpath(path)) !== path
      )
        fail('RECOVERY_HOME');
    }
    for (const name of units) {
      const state = await helpers.serviceState(name);
      if (state.state !== 'inactive' || state.pid !== 0) fail('RECOVERY_SERVICES_ACTIVE');
      const path = at(`etc/systemd/system/${name}`),
        f = await protectedFile(path, root, uid, 0o644);
      try {
        if ((await f.readFile('utf8')) !== definitions[name]) fail('RECOVERY_UNIT_CHANGED');
      } finally {
        await f.close();
      }
    }
    const enabled = await run('/usr/bin/systemctl', ['is-enabled', ...units], { allowed: [0, 1] });
    if (enabled.code !== 1 || enabled.stdout !== 'disabled\ndisabled') fail('RECOVERY_BOOT_STATE');
    const names = (await readdir(updater)).filter((name) =>
      /^initial-install-[a-f0-9-]{36}$/.test(name)
    );
    if (names.length !== 1) fail('RECOVERY_ATTEMPT');
    const oldAttempt = join(updater, names[0]);
    await protectedDirectory(oldAttempt, root, uid);
    if (((await lstat(oldAttempt)).mode & 0o7777) !== 0o700) fail('RECOVERY_ATTEMPT');
    recoveryInput = await json(join(oldAttempt, 'worker-input.json'), root, uid);
    recoveryBackup = await json(join(oldAttempt, 'database-backup.json'), root, uid);
    if (
      recoveryInput.helpers !== helperDirectory ||
      recoveryInput.backups !== join(updater, 'backups') ||
      JSON.stringify(identity({ ...recoveryInput.expected, configured: true })) !==
        JSON.stringify(recoveryInput.expected) ||
      !/^\.famynex-backup-[A-Za-z0-9_-]{6,32}$/.test(recoveryBackup.name ?? '')
    )
      fail('RECOVERY_BACKUP');
    // Explicit operator recovery claims a nested lock; it never clears a stale lock to retry.
    recoveryClaim = join(lock, 'disabled-calendar-recovery');
    try {
      await mkdir(recoveryClaim, { mode: 0o700 });
    } catch {
      fail('RECOVERY_BUSY');
    }
    await sync(lock);
    await write(
      join(updater, 'initial-core-recovery-original.json'),
      JSON.stringify(originalJournal)
    );
  } else {
    // Refusing an already installed device must not leave a new operation lock.
    await freshPaths();
    try {
      await mkdir(lock, { mode: 0o700 });
    } catch (e) {
      if (e.code === 'EEXIST') fail('BUSY');
      throw e;
    }
  }
  await sync(installation);
  let startAttempted = false,
    committed = false;
  const journal = async (phase) =>
    helpers.writePrivateJSON(updater, 'initial-core.json', {
      formatVersion: 1,
      phase,
      version: pins.version,
      sha256: pins.sha256
    });
  try {
    if (!recoverDisabledCalendar) {
      await freshPaths();
      for (const type of ['passwd', 'group']) {
        const answer = await run('/usr/bin/getent', [type, 'famynex'], { allowed: [0, 2] });
        if (answer.code !== 2 || answer.stdout) fail('UNMANAGED_ACCOUNT');
      }
      for (const name of units) {
        for (const directory of [
          'etc/systemd/system',
          'run/systemd/system',
          'usr/lib/systemd/system'
        ]) {
          for (const suffix of ['', '.d', '.wants', '.requires'])
            await absent(at(`${directory}/${name}${suffix}`));
        }
        const status = await run('/usr/bin/systemctl', ['show', name, '--property=LoadState']);
        if (status.stdout !== 'LoadState=not-found') fail('UNMANAGED_UNIT');
      }
    }
    if (!(await available(root))) fail('PORT_IN_USE');
    const verified = await helpers.reviewStage({
      parent: join(updater, 'staging'),
      stageName: basename(record.stagingDirectory),
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
      verified.sha256 !== pins.sha256 ||
      verified.version !== pins.version ||
      verified.sequence !== pins.sequence ||
      verified.sourceCommit !== pins.sourceCommit ||
      verified.sourceTree !== pins.sourceTree ||
      verified.targetSchema !== pins.schema ||
      verified.requiresMigration !== false
    )
      fail('RELEASE');
    if (recoverDisabledCalendar) {
      const previous = await helpers.reviewBackup({
        parent: join(updater, 'backups'),
        name: recoveryBackup.name,
        expected: recoveryInput.expected
      });
      if (previous.sha256 !== recoveryBackup.sha256 || previous.bytes !== recoveryBackup.bytes)
        fail('RECOVERY_BACKUP');
    }
    await journal(recoverDisabledCalendar ? 'recovery-validated' : 'validated');
    const attempt = join(
        updater,
        `${recoverDisabledCalendar ? 'initial-recovery' : 'initial-install'}-${randomUUID()}`
      ),
      backups = join(updater, 'backups');
    await mkdir(attempt, { mode: 0o700 });
    try {
      await mkdir(backups, { mode: 0o700 });
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
    }
    await protectedDirectory(backups, root, uid);
    if (((await lstat(backups)).mode & 0o7777) !== 0o700) fail('BACKUP_PARENT');
    const expected = await peer(run);
    // No supplied JSON/receipt can choose a different household or schema.
    if (JSON.stringify(identity({ ...expected, configured: true })) !== JSON.stringify(expected))
      fail('HOUSEHOLD_OR_SCHEMA');
    if (
      recoverDisabledCalendar &&
      JSON.stringify(expected) !== JSON.stringify(recoveryInput.expected)
    )
      fail('RECOVERY_HOUSEHOLD');
    const context = { root, uid, updater, attempt, coreEnvironment };
    await write(
      join(attempt, 'worker-input.json'),
      JSON.stringify({ expected, backups, helpers: helperDirectory })
    );
    await write(join(attempt, 'database-worker.mjs'), workerCode);
    await journal('backup-started');
    const backup = await database('backup', context, run);
    if (
      !/^\.famynex-backup-[A-Za-z0-9_-]{6,32}$/.test(backup?.name ?? '') ||
      !/^[a-f0-9]{64}$/.test(backup.sha256) ||
      !Number.isSafeInteger(backup.bytes) ||
      backup.bytes < 1 ||
      backup.archiveDecoded !== true ||
      typeof backup.calendarEnabled !== 'boolean'
    )
      fail('BACKUP');
    const calendarEnabled = backup.calendarEnabled;
    if (recoverDisabledCalendar && calendarEnabled) fail('RECOVERY_CALENDAR_POLICY');
    const activeUnits = calendarEnabled ? units : [units[0]];
    await journal('backup-ready');
    if (!recoverDisabledCalendar) {
      await run('/usr/sbin/useradd', [
        '--system',
        '--user-group',
        '--home-dir',
        '/var/lib/famynex',
        '--no-create-home',
        '--shell',
        '/bin/bash',
        '--comment',
        'Famynex',
        'famynex'
      ]);
      const accountUid = await numeric('-u'),
        accountGid = await numeric('-g');
      for (const name of ['var/lib/famynex', 'var/cache/famynex', 'var/lib/famynex/browser']) {
        await mkdir(at(name), { mode: 0o700 });
        await chmod(at(name), 0o700);
        await chown(at(name), accountUid, accountGid);
        await sync(dirname(at(name)));
      }
      await journal('account-created');
      await protectedDirectory(at('etc/systemd/system'), root, uid);
      for (const name of units)
        await write(at(`etc/systemd/system/${name}`), definitions[name], 0o644);
      await journal('units-written');
    }
    await run('/usr/bin/systemctl', ['daemon-reload']);
    for (const name of units) {
      const loaded = await run('/usr/bin/systemctl', [
        'show',
        name,
        '--property=FragmentPath',
        '--property=DropInPaths',
        '--property=User'
      ]);
      const values = Object.fromEntries(
        loaded.stdout.split('\n').map((line) => line.split(/=(.*)/s).slice(0, 2))
      );
      if (
        values.FragmentPath !== at(`etc/systemd/system/${name}`) ||
        values.DropInPaths !== '' ||
        values.User !== 'famynex'
      )
        fail('UNIT_CONFIGURATION');
    }
    const beforeStart = await database('before-start', context, run);
    if (beforeStart.verified !== true || beforeStart.calendarEnabled !== calendarEnabled)
      fail('DATABASE_OR_CALENDAR_POLICY');
    if (!(await available(root))) fail('PORT_IN_USE');
    if (!recoverDisabledCalendar)
      await symlink(`releases/${pins.sha256}`, join(installation, 'current'));
    await sync(installation);
    await journal('current-linked');
    startAttempted = true;
    await journal('starting');
    await run('/usr/bin/systemctl', ['start', ...activeUnits], { timeoutMs: 120000 });
    const checkProcess = async () => {
      const pids = [];
      for (const [index, name] of activeUnits.entries()) {
        const state = await helpers.serviceState(name);
        if (state.state !== 'active' || state.pid < 1) fail('NOT_ACTIVE');
        const cwd = await realpath(join(processRoot ?? at('proc'), String(state.pid), 'cwd'));
        if (cwd !== (index === 0 ? join(release, 'apps/web') : release)) fail('PROCESS_RELEASE');
        pids.push(state.pid);
      }
      if (!calendarEnabled) {
        const state = await helpers.serviceState(units[1]);
        if (state.state !== 'inactive' || state.pid !== 0) fail('DISABLED_CALENDAR_ACTIVE');
      }
      if ((await readlink(join(installation, 'current'))) !== `releases/${pins.sha256}`)
        fail('CURRENT');
      return pids;
    };
    const before = await checkProcess();
    if (
      !(await helpers.waitForCore({ ...(fetchHealth ? { fetchHealth } : {}), deadlineMs: 85000 }))
    )
      fail('HEALTH');
    if (JSON.stringify(await checkProcess()) !== JSON.stringify(before)) fail('PROCESS_CHANGED');
    const afterHealth = await database('after-health', context, run);
    if (afterHealth.verified !== true || afterHealth.calendarEnabled !== calendarEnabled)
      fail('DATABASE_OR_CALENDAR_POLICY');
    await journal('healthy');
    const installedDirectory = join(updater, 'installed');
    await mkdir(installedDirectory, { mode: 0o700 });
    const value = {
      formatVersion: 1,
      version: pins.version,
      sequence: pins.sequence,
      sha256: pins.sha256,
      sourceTree: pins.sourceTree,
      schemaVersion: pins.schema
    };
    await helpers.provisionInstalledState({ directory: installedDirectory, value });
    committed = true;
    if (
      JSON.stringify(await helpers.readInstalledState(installedDirectory)) !== JSON.stringify(value)
    )
      fail('INSTALLED_STATE');
    await journal('installed-state-committed');
    await run('/usr/bin/systemctl', ['enable', ...activeUnits]);
    const enabled = await run('/usr/bin/systemctl', ['is-enabled', ...activeUnits]);
    if (enabled.stdout !== activeUnits.map(() => 'enabled').join('\n')) fail('BOOT_ENABLE');
    if (!calendarEnabled) {
      const disabled = await run('/usr/bin/systemctl', ['is-enabled', units[1]], {
        allowed: [0, 1]
      });
      if (disabled.code !== 1 || disabled.stdout !== 'disabled') fail('CALENDAR_BOOT_POLICY');
    }
    if (JSON.stringify(await checkProcess()) !== JSON.stringify(before)) fail('PROCESS_CHANGED');
    await journal('completed');
    if (recoveryClaim) {
      await rmdir(recoveryClaim);
      await sync(lock);
    }
    await rmdir(lock);
    await sync(installation);
    return {
      kind: 'famynex-initial-core-installation',
      version: pins.version,
      sequence: pins.sequence,
      sha256: pins.sha256,
      installed: true,
      activated: true,
      coreDatabaseReady: true,
      calendarActive: calendarEnabled,
      calendarEnabled,
      recoveredInitialInstallation: recoverDisabledCalendar,
      servicesEnabled: true,
      freshBackupVerified: true,
      migrationApplied: false,
      keysRegenerated: false,
      kioskEnrolled: false,
      hardwareAccepted: false
    };
  } catch (error) {
    if (startAttempted && !committed)
      await run(
        '/usr/bin/systemctl',
        ['stop', 'famynex-calendar.service', 'famynex-core.service'],
        { timeoutMs: 75000 }
      ).catch(() => {});
    // No guessed rollback, database restore, account removal, current deletion or
    // automatic lock clearing. A committed healthy release is retained on enable failure.
    if (error instanceof InitialCoreError) throw error;
    fail('REVIEW_REQUIRED');
  }
}

async function main() {
  if (
    !(
      process.argv.length === 2 ||
      (process.argv.length === 3 && process.argv[2] === '--recover-disabled-calendar')
    ) ||
    process.platform !== 'linux' ||
    process.arch !== 'x64' ||
    process.getuid() !== 0 ||
    process.versions.node.split('.')[0] !== '22'
  )
    fail('HOST_OR_ARGUMENTS');
  const directory = `/opt/famynex/releases/${approval.sha256}/runtime/updater`;
  await protectedDirectory(directory, '/', 0);
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
        'linux-appliance-updater-store.mjs',
        'linux-appliance-installed-state.mjs',
        'linux-appliance-systemd.mjs',
        'linux-appliance-wait-ready.mjs',
        'linux-appliance-backup.mjs'
      ].map(load)
    ))
  );
  console.info(
    'Mevcut ev dogrulanip yeni yedek aliniyor. Ardindan Core ve takvim servisleri kurulacak...'
  );
  console.info(
    JSON.stringify(
      await installInitialCore({
        helpers,
        recoverDisabledCalendar: process.argv[2] === '--recover-disabled-calendar'
      }),
      null,
      2
    )
  );
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  main().catch((error) => {
    console.error(
      error instanceof InitialCoreError
        ? error.message
        : 'Initial Core installation requires review. Keep the saved home and operation lock.'
    );
    process.exitCode = 1;
  });
