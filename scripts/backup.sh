#!/bin/bash
# Dumps the PostgreSQL database from the running `db` container into ./backups,
# keeping the last 14 daily backups. Intended to run from a host cron job, e.g.:
#   0 2 * * * cd /path/to/k3-siem && ./scripts/backup.sh >> /var/log/k3-siem-backup.log 2>&1
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p backups
TS=$(date +%Y%m%d-%H%M%S)
OUT="backups/k3-siem-${TS}.sql.gz"

docker compose exec -T db pg_dump -U k3 -d k3_siem | gzip > "$OUT"
echo "[Backup] Wrote $OUT ($(du -h "$OUT" | cut -f1))"

# Retain the last 14 backups
ls -1t backups/k3-siem-*.sql.gz 2>/dev/null | tail -n +15 | xargs -r rm -f
