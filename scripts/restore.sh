#!/bin/bash
# Restores a PostgreSQL dump created by backup.sh into the running `db` container.
# Usage: ./scripts/restore.sh backups/k3-siem-20260615-020000.sql.gz
set -euo pipefail
cd "$(dirname "$0")/.."

FILE="${1:?Usage: ./scripts/restore.sh <backup-file.sql.gz>}"
[ -f "$FILE" ] || { echo "File not found: $FILE"; exit 1; }

echo "WARNING: this will DROP and recreate the k3_siem database. Press Ctrl+C to abort, Enter to continue."
read -r _

docker compose exec -T db psql -U k3 -d postgres -c "DROP DATABASE IF EXISTS k3_siem;"
docker compose exec -T db psql -U k3 -d postgres -c "CREATE DATABASE k3_siem OWNER k3;"
gunzip -c "$FILE" | docker compose exec -T db psql -U k3 -d k3_siem
echo "[Restore] Done. Restart the app container: docker compose restart app"
