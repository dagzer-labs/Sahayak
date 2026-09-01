#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${BACKUP_PATH:?BACKUP_PATH is required}"

umask 077
pg_dump --format=custom --no-owner --no-privileges --dbname="$DATABASE_URL" --file="$BACKUP_PATH"
sha256sum "$BACKUP_PATH" > "$BACKUP_PATH.sha256"
pg_restore --list "$BACKUP_PATH" >/dev/null
