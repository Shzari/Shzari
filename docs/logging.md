# Logging Overview

## Log Files

Default directory: `logs/` (project root)

- `logs/app.log`
  - All application runtime logs at `APP_LOG_LEVEL` and above.
  - Includes request start/finish, login events, action events, and audit event summaries.
- `logs/error.log`
  - Error-level events only.
  - Includes uncaught request exceptions with traceback context.

## Environment Variables

- `APP_LOG_DIR`
  - Override log directory path.
  - Default: `logs` under project root.
- `APP_LOG_LEVEL`
  - Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`).
  - Default: `INFO`.
- `APP_LOG_MAX_BYTES`
  - Max size per log file before rotation.
  - Default: `10485760` (10 MB).
- `APP_LOG_BACKUP_COUNT`
  - Number of rotated files to keep.
  - Default: `10`.
- `APP_LOG_TO_STDOUT`
  - `1` to mirror logs to stdout.
  - Default: `1`.

## What Is Logged

- Every request start:
  - request id, method, path, endpoint, user, role, client IP
- Every request finish:
  - request id, status code, duration (ms), user, role, client IP
- Unhandled request exceptions:
  - traceback + request context
- Login events:
  - username, auth source, success/failure, reason, IP
- App action events:
  - action, user, role, device/interface, status, IP
- Audit events:
  - action + actor + device + detail key list
