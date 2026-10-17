# Configuration recovery and database restore

## Configuration activation

Settings, WAF/network API changes, CatAI actions and snapshot/template restores
use configTx. Application discovery, edge-ban updates, audit-log repointing and
Cloudflare origin locking also use its validated publication path. Explicit
save-only/draft operations still persist without activating Caddy.

The writer holds the process-shared configuration lock and a SQLite IMMEDIATE
transaction. Rendering writes a new immutable asset generation. The candidate
Caddyfile is validated before publication. A private, fsynced recovery journal
records the previous file; the commit marker shares the settings transaction.
A failed validation, reload of a reachable Caddy, or database commit rolls back
SQLite, the file and the running configuration. If rollback reload fails, the
result says recoveryRequired and leaves the journal for recovery. Startup and
subsequent CLI mutations recover that journal before proceeding.

This coordinates recoverable activation; it does not make SQLite and Caddy one
indivisible distributed commit. In-flight requests can straddle an activation,
and recovery runs when CatWAF resumes. A stopped Caddy may have a validated
configuration saved for its next start. Raw manual file edits and external
nginx/Apache deployment are outside this transaction.

Generated assets are retained with old Caddyfiles so rollback remains possible.
Include data/caddy/generations in backups. They are not automatically garbage
collected: monitor disk space and remove a generation only after confirming no
active or retained Caddyfile references it. Do not delete config-transaction.json
or SQLite coordination files to bypass an active recovery/restore refusal.

## Native offline database restore

1. Stop the API, scheduler, CLI workers and Caddy, including any old-version
   processes. Keep .env, Caddyfile, generated assets and the encryption passphrase
   in an access-restricted recovery backup.
2. With the updated source and a Caddy/Coraza binary on PATH, run:

   ```bash
   node bin/catwaf.js backup restore /absolute/path/backup.json --db --confirm-db-restore
   ```

   Use backup.json.enc for an encrypted backup. The matching .db or .db.enc must
   be alongside it. Redacted manifests require an explicit --allow-redacted and
   cannot reconstruct removed credentials.
3. Check success and retain the reported private pre-restore recovery copy.
   The CLI restores SQLite, applies the matching manifest through validation,
   and reports when services can restart. Every restored session is revoked.
4. Restart services and verify health, admin login, ordinary traffic and WAF
   blocking against your real configuration.

Restore obtains EXCLUSIVE access to a separate coordination database. Other
updated CatWAF processes retain SHARED leases even while idle, so an open process
blocks restore. The OS releases crashed-process locks. Old releases and unrelated
SQLite tools do not participate: stop them explicitly during migration.

The source is staged and checked for integrity and compatible schema before the
live DB is touched. SQLite's backup API preserves the destination inode and uses
SQLite transactions; the code never unlinks the live WAL or swaps the live file
under another connection. A consistent private recovery copy is retained.

If manifest application fails after copying the database, services remain stopped
and database_restore_pending blocks normal startup. Correct the cause and run
backup restore on the matching JSON manifest **without --db**. Only successful
Caddy validation clears the guard. A missing local Caddy binary cannot clear it.
A failed operation returns a nonzero CLI exit code and its recovery-copy path.

## Docker restore

Stop the stack without deleting volumes. Run the updated backend image once,
without starting dependencies, against the same named volumes and environment:

```bash
docker compose stop
docker compose run --rm --no-deps backend node bin/catwaf.js backup restore /app/data/backups/backup.json --db --confirm-db-restore
docker compose up -d
```

Restart only after the restore command succeeds. Use the actual backup filename;
external backups can be mounted read-only into the one-shot container. Existing
volume ownership and the admin Unix socket configuration still require the
migration described in security-audit-2026-10-16.md. Never use down -v to upgrade
or restore: it removes the database volumes.

## Verification

security-recovery.test.js injects mutation, validation, reload, rollback and
commit failures and actual child-process crashes before/after commit. It checks
immutable assets, separate readers, stale-lock recovery, offline access refusal,
schema rejection, session revocation and the incomplete-restore guard.
restore-e2e.test.js runs the real CLI, SQLite and Caddy validator. It passed on
native Linux and inside the Node 24 Alpine backend container. These are local
filesystem/process tests, not power-loss or network-filesystem certification.

The follow-up storage suite checks atomic settings/revision writes, corrupt
policy state, audit journal errors and preservation of both log paths when a
configuration rollback remains unresolved. SQLite's automatic rollback after
SQLITE_FULL is recognized using the connection's actual transaction state.

`sudo env PATH="$PATH" CATWAF_TEST_USER="$(id -un)" bash scripts/check-filesystem-reliability.sh`
runs nine real fault checks as an unprivileged user in a private mount namespace
with a fresh 32 MiB tmpfs. It exhausts that filesystem, denies directory writes,
forces SQLite page exhaustion, kills a configuration writer immediately after
publication, and verifies refusal of corrupt journals and truncated backups.
It mounts no existing data directory. These tests passed on Linux/amd64; block
device EIO, physical power loss and network filesystem behavior remain untested.
