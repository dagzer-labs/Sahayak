#!/bin/sh
set -eu

: "${RESTORE_DATABASE_URL:?RESTORE_DATABASE_URL is required}"
: "${BACKUP_PATH:?BACKUP_PATH is required}"

sha256sum -c "$BACKUP_PATH.sha256"
pg_restore --clean --if-exists --no-owner --no-privileges --exit-on-error \
  --dbname="$RESTORE_DATABASE_URL" "$BACKUP_PATH"
psql "$RESTORE_DATABASE_URL" --set ON_ERROR_STOP=1 --command \
  "SELECT postgis_version(); SELECT version, description, success FROM _sqlx_migrations ORDER BY version;"
