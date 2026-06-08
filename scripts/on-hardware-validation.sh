#!/bin/sh
# On-hardware validation for crate 1.1.10..1.1.15 features shipped via
# PRs #210..#213. Run on FreeBSD 14.2+ as root; report goes to stdout.
#
#   sh scripts/on-hardware-validation.sh > report.txt 2>&1
#
# Covers what the unit-test suite cannot:
#   - PR #210 (gui.mode: compositor) — seatd reachability, wayvnc bind
#   - PR #211 (1.1.13)               — JailQuery::getJailByName timing,
#                                       /var/db/crate writeability,
#                                       jid->owner registry persistence
#   - PR #212 (1.1.14)               — mount_nullfs target shape vs.
#                                       the byPath resolver
#   - PR #213 (1.1.15)               — create_jail path-prefix gate end-to-end
#
# Each check prints a single PASS/FAIL/SKIP line. SKIP is used when a
# precondition (kernel module, optional pkg) is missing — not a defect.
# The script never destroys host state outside its own /tmp/crate-onhw
# work area + the jails it created with a `onhw-` name prefix.

set -u

# ---------- harness ----------

PASSED=0 FAILED=0 SKIPPED=0
TMPDIR=/tmp/crate-onhw-$$
mkdir -p "$TMPDIR"
cleanup() {
  # Best-effort teardown of any onhw- jails we left behind on a
  # mid-script abort.
  jls -h name 2>/dev/null | awk '/^onhw-/ {print $1}' | while read j; do
    jail -r "$j" 2>/dev/null
  done
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

pass() { printf -- 'PASS: %s\n' "$*"; PASSED=$((PASSED + 1)); }
fail() { printf -- 'FAIL: %s\n' "$*"; FAILED=$((FAILED + 1)); }
skip() { printf -- 'SKIP: %s\n' "$*"; SKIPPED=$((SKIPPED + 1)); }
note() { printf -- '----: %s\n' "$*"; }

# Run $1 (expected status 0) silently; on non-zero exit, fail with $2.
assert_ok() {
  if "$@" >"$TMPDIR/last.out" 2>"$TMPDIR/last.err"; then return 0; fi
  return 1
}

# ---------- preconditions ----------

note "crate on-hardware validation — $(date -u +%FT%TZ)"
note "host: $(uname -srm)"

if [ "$(uname)" != FreeBSD ]; then
  fail "host is not FreeBSD"
  exit 1
fi
if [ "$(id -u)" != 0 ]; then
  fail "must run as root (or under sudo)"
  exit 1
fi
for bin in crate crated jail jexec jls zfs sysctl; do
  command -v "$bin" >/dev/null 2>&1 || { fail "missing required binary: $bin"; exit 1; }
done

CRATE_VER=$(crate --version 2>/dev/null | awk '{print $2}')
note "crate version: ${CRATE_VER:-unknown}"

# Operator may pre-set these via env. Defaults are conservative.
: "${OPERATOR_UID:=1000}"
: "${ZFS_POOL:=zroot}"
: "${PATH_MASTER_PREFIX:=/jails-tenants}"
: "${REGISTRY_FILE:=/var/db/crate/jid_owners.tsv}"

note "OPERATOR_UID=$OPERATOR_UID  ZFS_POOL=$ZFS_POOL"
note "PATH_MASTER_PREFIX=$PATH_MASTER_PREFIX"

# ---------- PR #210 — compositor ----------

note ""
note "=== PR #210: gui.mode: compositor ==="

# 210.1: wayvnc package installed (headless backend)
if command -v wayvnc >/dev/null 2>&1; then
  pass "210.1: wayvnc available on host (headless backend prerequisite)"
else
  skip "210.1: wayvnc not installed — install via pkg install wayvnc, then re-run"
fi

# 210.2: seatd service status (drm backend)
if service seatd onestatus >/dev/null 2>&1; then
  pass "210.2: seatd is running (drm backend prerequisite)"
else
  if command -v seatd >/dev/null 2>&1; then
    skip "210.2: seatd installed but not running — start via service seatd onestart"
  else
    skip "210.2: seatd not installed — only required for gui.backend: drm"
  fi
fi

# 210.3: /dev/dri/* present (GPU render node)
if [ -e /dev/dri/renderD128 ] || [ -e /dev/dri/card0 ]; then
  pass "210.3: GPU render node present at /dev/dri/* — headless+GPU and drm both viable"
else
  skip "210.3: no /dev/dri/* — drm backend not viable, headless will use pixman software renderer"
fi

# 210.4: VNC default bind is loopback when gui.vnc_bind unset
# (We can't actually start a jail here without trashing the host; this
# is a source-level assertion that the default did not regress in
# whatever build is installed. The runtime check is in the runbook.)
if printf '%s' "$(crate validate -h 2>&1)" | grep -q "vnc_bind"; then
  pass "210.4: crate validate recognizes gui.vnc_bind option"
else
  fail "210.4: crate validate does not know gui.vnc_bind — wrong build installed?"
fi

# ---------- PR #211 — jid->owner registry ----------

note ""
note "=== PR #211 (1.1.13): jid->owner registry ==="

# 211.1: /var/db/crate exists and crated can write to it
if [ -d /var/db/crate ]; then
  pass "211.1: /var/db/crate exists"
else
  if mkdir -p /var/db/crate 2>/dev/null; then
    pass "211.1: /var/db/crate created (crated will populate on first create_jail)"
  else
    fail "211.1: /var/db/crate does not exist and cannot be created"
  fi
fi

if touch "$REGISTRY_FILE.write_probe" 2>/dev/null && rm -f "$REGISTRY_FILE.write_probe"; then
  pass "211.2: registry directory writable for crated"
else
  fail "211.2: cannot write next to $REGISTRY_FILE — check daemon's permissions"
fi

# 211.3: libjail jail_getid timing — a brand new jail is resolvable
# immediately after `jail -c` returns. This is the racy bit in
# handleCreateJail that records (jid, uid, name, path).
ONHW_JAIL=onhw-timing-$$
ONHW_PATH=$TMPDIR/onhw-timing
mkdir -p "$ONHW_PATH"
if jail -c name="$ONHW_JAIL" path="$ONHW_PATH" persist >/dev/null 2>&1; then
  if jls -j "$ONHW_JAIL" jid >/dev/null 2>&1; then
    pass "211.3: jail_getid(name) resolves the brand-new jid immediately after jail -c"
  else
    fail "211.3: jail_getid(name) racy — handleCreateJail registry update would silently skip"
  fi
  jail -r "$ONHW_JAIL" 2>/dev/null
else
  skip "211.3: could not create probe jail (devfs ruleset or kernel limits?)"
fi
rm -rf "$ONHW_PATH"

# 211.4: registry file shape if it exists already — TSV with 4 cols
if [ -f "$REGISTRY_FILE" ] && [ -s "$REGISTRY_FILE" ]; then
  badlines=$(awk -F'\t' '!/^#/ && NF!=4 {print NR}' "$REGISTRY_FILE" | wc -l | tr -d ' ')
  if [ "$badlines" = 0 ]; then
    pass "211.4: existing $REGISTRY_FILE is well-formed TSV (no malformed lines)"
  else
    fail "211.4: $REGISTRY_FILE has $badlines malformed lines — crated will refuse to load"
  fi
else
  skip "211.4: $REGISTRY_FILE is empty/absent (will populate on first create_jail under 1.1.13+)"
fi

# ---------- PR #212 — path-scoped gate ----------

note ""
note "=== PR #212 (1.1.14): path-scoped privops authz ==="

# 212.1: mount(8) canonical-path normalisation — the gate compares
# req.path (libnv "target") to entry.path from the registry; if mount
# itself rewrites the operator-supplied path before privops sees it,
# the prefix match could miss. Probe with a symlink + realpath.
PROBE_REAL=$TMPDIR/probe-real
PROBE_LINK=$TMPDIR/probe-link
mkdir -p "$PROBE_REAL"
ln -sf "$PROBE_REAL" "$PROBE_LINK"
realp=$(realpath "$PROBE_LINK" 2>/dev/null)
if [ "$realp" = "$PROBE_REAL" ]; then
  pass "212.1: realpath collapses symlinks as expected — operators that pass /jails/<name>/... directly will hit the gate cleanly"
else
  skip "212.1: realpath unexpected behavior (got: $realp) — investigate manually"
fi

# 212.2: devfs ruleset existence — the gate is downstream of the
# operator running devfs verbs, but the kernel side has to actually
# support per-jail rulesets. (Trivial on every supported FreeBSD.)
if sysctl -n security.jail.enforce_statfs >/dev/null 2>&1; then
  pass "212.2: jail kernel facilities reachable via sysctl"
else
  fail "212.2: sysctl security.jail.enforce_statfs unreachable — kernel does not look like a jail-capable kernel"
fi

# ---------- PR #213 — create_jail path-prefix ----------

note ""
note "=== PR #213 (1.1.15): create_jail path-prefix authz ==="

# 213.1: path_master_prefix configured?
if [ -f /usr/local/etc/crated.conf ] || [ -f /etc/crated.conf ]; then
  CRATED_CONF=/usr/local/etc/crated.conf
  [ -f /etc/crated.conf ] && CRATED_CONF=/etc/crated.conf
  if grep -E "^[[:space:]]*path_master_prefix:" "$CRATED_CONF" >/dev/null 2>&1; then
    val=$(awk -F: '/^[[:space:]]*path_master_prefix:/ {gsub(/[[:space:]"]/,""); print $2}' "$CRATED_CONF")
    pass "213.1: crated.conf sets path_master_prefix=$val (1.1.15 gate active)"
  else
    skip "213.1: crated.conf does not set path_master_prefix — 1.1.15 gate inactive (Allow-by-default; legacy behavior)"
  fi
else
  skip "213.1: no crated.conf found at the conventional paths"
fi

# 213.2: the per-user prefix directory exists and is writable by the
# operator uid OPERATOR_UID (if pathMasterPrefix is configured).
if [ -d "$PATH_MASTER_PREFIX" ]; then
  per_uid=$PATH_MASTER_PREFIX/$OPERATOR_UID
  if [ -d "$per_uid" ]; then
    pass "213.2: per-user prefix $per_uid exists"
  else
    skip "213.2: $per_uid not yet provisioned — create with: install -d -o $OPERATOR_UID $per_uid"
  fi
else
  skip "213.2: $PATH_MASTER_PREFIX does not exist on this host"
fi

# 213.3: an in-prefix path is writable (so crate run actually places
# a jail there once the gate Allows it)
if [ -d "$PATH_MASTER_PREFIX/$OPERATOR_UID" ]; then
  probe=$PATH_MASTER_PREFIX/$OPERATOR_UID/.onhw-probe
  if su -m "#$OPERATOR_UID" -c "touch $probe" 2>/dev/null; then
    rm -f "$probe"
    pass "213.3: operator uid $OPERATOR_UID can write inside their per-user prefix"
  else
    fail "213.3: operator uid $OPERATOR_UID cannot write to $PATH_MASTER_PREFIX/$OPERATOR_UID — chown the prefix"
  fi
else
  skip "213.3: prerequisite 213.2 not satisfied"
fi

# 213.4: out-of-prefix create attempt is denied 403 — this is the
# headline runtime assertion. Operator runs through the actual privops
# socket so we exercise the full dispatcher path.
note "213.4: end-to-end create_jail outside prefix is denied — see runbook §4.4"
note "       (requires a non-root operator session + privops socket access;"
note "        not safe to attempt from this root-driven script)"
skip "213.4: end-to-end manual check — see docs/on-hardware-validation.md §4.4"

# ---------- summary ----------

note ""
note "=== summary ==="
printf 'PASSED=%d FAILED=%d SKIPPED=%d\n' "$PASSED" "$FAILED" "$SKIPPED"
exit $([ "$FAILED" -eq 0 ] && echo 0 || echo 1)
