#!/bin/sh
# Matrix Synapse backup script for crate containers
#
# Usage: ./examples/matrix/matrix-backup.sh [BACKUP_DIR]
#
# Backs up: database dump, Synapse config + signing keys, media store.
# Designed to run from the host where crate containers are managed.

BACKUP_DIR="${1:-$HOME/matrix/backups}"
DATE=$(date +%Y%m%d_%H%M%S)
KEEP_DAYS=14

mkdir -p "$BACKUP_DIR"

echo "Starting Matrix backup: ${DATE}"

# --- Database dump ---
echo "  Dumping database..."
crate console matrix-synapse -- su -m postgres -c "pg_dump synapse" 2>/dev/null | \
    gzip > "${BACKUP_DIR}/synapse_db_${DATE}.sql.gz"

if [ -f "${BACKUP_DIR}/synapse_db_${DATE}.sql.gz" ]; then
    echo "  Database: $(du -h "${BACKUP_DIR}/synapse_db_${DATE}.sql.gz" | awk '{print $1}')"
else
    echo "  WARNING: Database dump failed"
fi

# --- Config backup (from shared dirs on host) ---
echo "  Backing up config..."
tar czf "${BACKUP_DIR}/synapse_config_${DATE}.tar.gz" \
    "$HOME/matrix/synapse/homeserver.yaml" \
    "$HOME/matrix/synapse/log.config" \
    "$HOME/matrix/synapse/"*.signing.key \
    "$HOME/matrix/nginx/conf.d/" \
    2>/dev/null

echo "  Config: $(du -h "${BACKUP_DIR}/synapse_config_${DATE}.tar.gz" 2>/dev/null | awk '{print $1}')"

# --- Media backup (incremental with rsync if available) ---
echo "  Backing up media store..."
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$HOME/matrix/synapse/media_store/" "${BACKUP_DIR}/media_store/"
    echo "  Media: $(du -sh "${BACKUP_DIR}/media_store" 2>/dev/null | awk '{print $1}')"
else
    tar czf "${BACKUP_DIR}/synapse_media_${DATE}.tar.gz" "$HOME/matrix/synapse/media_store/" 2>/dev/null
    echo "  Media: $(du -h "${BACKUP_DIR}/synapse_media_${DATE}.tar.gz" 2>/dev/null | awk '{print $1}')"
fi

# --- Cleanup old backups ---
find "${BACKUP_DIR}" -name "synapse_*" -mtime +${KEEP_DAYS} -delete 2>/dev/null

echo ""
echo "Backup complete: ${BACKUP_DIR}"
ls -lh "${BACKUP_DIR}"/synapse_*_${DATE}* 2>/dev/null
