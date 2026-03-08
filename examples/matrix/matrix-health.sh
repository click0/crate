#!/bin/sh
# Matrix Synapse health check for crate containers
#
# Usage: ./examples/matrix/matrix-health.sh [DOMAIN]
#
# Checks service status inside each crate container and tests
# federation/client API endpoints externally.

DOMAIN="${1:-matrix.example.com}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

ok()   { printf "  %-20s ${GREEN}OK${NC}\n" "$1"; }
fail() { printf "  %-20s ${RED}FAILED${NC}\n" "$1"; }

echo "=== Matrix Synapse Health (crate) ==="
echo ""

# --- Container status ---
echo "--- Containers ---"
for name in synapse nginx coturn; do
    if crate status "matrix-${name}" >/dev/null 2>&1; then
        ok "$name"
    else
        fail "$name"
    fi
done

# --- Services inside containers ---
echo ""
echo "--- Services ---"
for pair in "synapse:postgresql synapse" "nginx:nginx" "coturn:turnserver"; do
    container="${pair%%:*}"
    services="${pair#*:}"
    for svc in $services; do
        if crate console "matrix-${container}" -- service "$svc" status >/dev/null 2>&1; then
            ok "${container}/${svc}"
        else
            fail "${container}/${svc}"
        fi
    done
done

# --- API endpoints ---
echo ""
echo "--- API Endpoints ---"

CLIENT_CODE=$(curl -s -o /dev/null -w '%{http_code}' "https://${DOMAIN}/_matrix/client/versions" 2>/dev/null)
if [ "$CLIENT_CODE" = "200" ]; then
    ok "Client API (${CLIENT_CODE})"
else
    fail "Client API (${CLIENT_CODE})"
fi

FED_CODE=$(curl -s -o /dev/null -w '%{http_code}' "https://${DOMAIN}:8448/_matrix/federation/v1/version" 2>/dev/null)
if [ "$FED_CODE" = "200" ]; then
    ok "Federation (${FED_CODE})"
else
    fail "Federation (${FED_CODE})"
fi

WELL_KNOWN=$(curl -s -o /dev/null -w '%{http_code}' "https://${DOMAIN}/.well-known/matrix/server" 2>/dev/null)
if [ "$WELL_KNOWN" = "200" ]; then
    ok ".well-known (${WELL_KNOWN})"
else
    fail ".well-known (${WELL_KNOWN})"
fi

# --- Resources ---
echo ""
echo "--- Resources ---"
DB_SIZE=$(crate console matrix-synapse -- su -m postgres -c "psql -t -c \"SELECT pg_size_pretty(pg_database_size('synapse'));\"" 2>/dev/null | tr -d ' ')
printf "  %-20s %s\n" "DB size:" "${DB_SIZE:-N/A}"

MEDIA_SIZE=$(du -sh "$HOME/matrix/synapse/media_store" 2>/dev/null | awk '{print $1}')
printf "  %-20s %s\n" "Media store:" "${MEDIA_SIZE:-N/A}"

echo ""
echo "Test federation: https://federationtester.matrix.org/#${DOMAIN}"
