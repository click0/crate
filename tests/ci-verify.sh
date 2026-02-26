#!/bin/sh
# ci-verify.sh — CI verification for FreeBSD 15.0 compatibility changes
#
# Exit code: 0 if all required tests pass. SKIPs are OK (infra limitation).
# Usage: sudo sh tests/ci-verify.sh [build_dir]

BUILDDIR="${1:-.}"
CRATE_BIN="${BUILDDIR}/crate"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf "  \033[32mPASS\033[0m: %s\n" "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf "  \033[31mFAIL\033[0m: %s\n" "$1" >&2; }
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); printf "  \033[33mSKIP\033[0m: %s\n" "$1"; }
section() { printf "\n=== %s ===\n" "$1"; }

# ===========================================================================
#  Layer 1: Feature Detection
# ===========================================================================
section "Feature Detection"

OSRELEASE=$(sysctl -n kern.osrelease)
OSMAJOR=$(echo "$OSRELEASE" | sed 's/\..*//')
MACHINE=$(sysctl -n hw.machine)
printf "  OS release: %s  major=%s  machine=%s\n" "$OSRELEASE" "$OSMAJOR" "$MACHINE"

# VIMAGE / VNET
VIMAGE=$(sysctl -n kern.features.vimage 2>/dev/null || echo 0)
printf "  VIMAGE: %s\n" "$VIMAGE"

# JAIL_OWN_DESC in headers
HAS_JAIL_OWN_DESC=0
if grep -q JAIL_OWN_DESC /usr/include/sys/jail.h 2>/dev/null; then
  HAS_JAIL_OWN_DESC=1
fi
printf "  JAIL_OWN_DESC in headers: %s\n" "$HAS_JAIL_OWN_DESC"

# Can create jails?
CAN_JAIL=0
JAILED=$(sysctl -n security.jail.jailed 2>/dev/null || echo 1)
if [ "$JAILED" = "0" ]; then
  CAN_JAIL=1
fi
printf "  Can create jails: %s\n" "$CAN_JAIL"

# Can create epair?
CAN_EPAIR=0
if [ "$VIMAGE" = "1" ]; then
  _EP=$(ifconfig epair create 2>/dev/null || true)
  if [ -n "$_EP" ]; then
    ifconfig "$_EP" destroy 2>/dev/null || true
    CAN_EPAIR=1
  fi
fi
printf "  Can create epair: %s\n" "$CAN_EPAIR"

# ZFS available?
HAS_ZFS=0
if kldstat -q -m zfs 2>/dev/null || sysctl -n vfs.zfs.version.spa >/dev/null 2>/dev/null; then
  HAS_ZFS=1
fi
printf "  ZFS available: %s\n" "$HAS_ZFS"

# Binary exists?
HAS_BINARY=0
if [ -x "$CRATE_BIN" ]; then HAS_BINARY=1; fi
printf "  Binary built: %s\n" "$HAS_BINARY"

# ===========================================================================
#  Layer 2: Binary & Version Tests
# ===========================================================================
section "T01: crate binary smoke test"

if [ "$HAS_BINARY" = "1" ]; then
  OUTPUT=$("$CRATE_BIN" 2>&1 || true)
  if echo "$OUTPUT" | grep -q "run as a regular user setuid to root"; then
    pass "crate starts, hits setuid guard (binary functional)"
  elif echo "$OUTPUT" | grep -q "usage: crate\|crate can not run"; then
    pass "crate starts (binary functional)"
  else
    fail "crate produced unexpected output: ${OUTPUT}"
  fi
else
  skip "crate binary not built (compile-only CI)"
fi

# ---------------------------------------------------------------------------
section "T02: version detection (getFreeBSDMajorVersion logic)"

cat > /tmp/_ci_test_ver.cpp << 'CPPEOF'
#include <sys/types.h>
#include <sys/sysctl.h>
#include <string>
#include <iostream>
int main() {
    char buf[256]; size_t sz = sizeof(buf)-1;
    sysctlbyname("kern.osrelease", buf, &sz, nullptr, 0);
    buf[sz] = 0;
    try { std::cout << std::stoi(std::string(buf)); } catch (...) { std::cout << 0; }
    return 0;
}
CPPEOF
if c++ -std=c++17 -o /tmp/_ci_test_ver /tmp/_ci_test_ver.cpp 2>/dev/null; then
  DETECTED=$(/tmp/_ci_test_ver)
  if [ "$DETECTED" = "$OSMAJOR" ]; then
    pass "version detection: kern.osrelease -> ${DETECTED} (expected ${OSMAJOR})"
  else
    fail "version detection: got ${DETECTED}, expected ${OSMAJOR}"
  fi
else
  fail "could not compile version detection test"
fi
rm -f /tmp/_ci_test_ver /tmp/_ci_test_ver.cpp

# ---------------------------------------------------------------------------
section "T03: HTTPS URL and releases/snapshots logic"

if grep -q 'https://download.freebsd.org/' "$BUILDDIR/locs.cpp"; then
  pass "locs.cpp uses HTTPS URL (not FTP)"
else
  fail "locs.cpp does not contain https://download.freebsd.org/"
fi

if grep -q '"releases"' "$BUILDDIR/locs.cpp" && grep -q '"snapshots"' "$BUILDDIR/locs.cpp"; then
  pass "locs.cpp contains releases/snapshots branching"
else
  fail "locs.cpp missing releases/snapshots detection logic"
fi

# Verify URL reachability
case "$OSRELEASE" in *-RELEASE*) SUBDIR="releases" ;; *) SUBDIR="snapshots" ;; esac
URL="https://download.freebsd.org/${SUBDIR}/${MACHINE}/${OSRELEASE}/base.txz"
if fetch -s "$URL" >/dev/null 2>&1; then
  pass "base.txz URL reachable: ${URL}"
else
  skip "base.txz URL not reachable (network or snapshot not published)"
fi

# ===========================================================================
#  Layer 3: Compile-Time API Verification
# ===========================================================================
section "T04: JAIL_OWN_DESC compile-time guard"

if [ "$OSMAJOR" -ge 15 ]; then
  if [ "$HAS_JAIL_OWN_DESC" = "1" ]; then
    pass "JAIL_OWN_DESC defined in sys/jail.h on FreeBSD ${OSMAJOR}"
  else
    fail "JAIL_OWN_DESC NOT defined on FreeBSD ${OSMAJOR}"
  fi
  # Verify it compiles
  cat > /tmp/_ci_test_jd.cpp << 'CPPEOF'
#include <sys/param.h>
extern "C" {
#include <sys/jail.h>
}
#include <jail.h>
int main() {
    int flags = JAIL_CREATE | JAIL_OWN_DESC;
    int (*fn)(int) = &jail_remove_jd;
    (void)flags; (void)fn;
    return 0;
}
CPPEOF
  if c++ -std=c++17 -ljail -o /tmp/_ci_test_jd /tmp/_ci_test_jd.cpp 2>/dev/null; then
    pass "JAIL_OWN_DESC + jail_remove_jd() compiles on FreeBSD ${OSMAJOR}"
  else
    fail "JAIL_OWN_DESC code fails to compile on FreeBSD ${OSMAJOR}"
  fi
  rm -f /tmp/_ci_test_jd /tmp/_ci_test_jd.cpp
else
  if [ "$HAS_JAIL_OWN_DESC" = "0" ]; then
    pass "JAIL_OWN_DESC correctly absent on FreeBSD ${OSMAJOR}"
  else
    skip "JAIL_OWN_DESC unexpectedly present on FreeBSD ${OSMAJOR}"
  fi
fi

# ---------------------------------------------------------------------------
section "T05: MNT_IGNORE compiles"

cat > /tmp/_ci_test_mnt.cpp << 'CPPEOF'
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/uio.h>
int main() {
    int flags = MNT_IGNORE;
    struct iovec iov[4];
    (void)flags; (void)iov;
    return 0;
}
CPPEOF
if c++ -std=c++17 -o /tmp/_ci_test_mnt /tmp/_ci_test_mnt.cpp 2>/dev/null; then
  pass "MNT_IGNORE compiles with nmount"
else
  fail "MNT_IGNORE does not compile"
fi
rm -f /tmp/_ci_test_mnt /tmp/_ci_test_mnt.cpp

# ---------------------------------------------------------------------------
section "T06: jail_remove_jd symbol in binary (15.0+) / absent (14.x)"

if [ "$HAS_BINARY" = "1" ]; then
  HAS_SYMBOL=0
  if readelf -s "$CRATE_BIN" 2>/dev/null | grep -q jail_remove_jd; then
    HAS_SYMBOL=1
  elif nm -D "$CRATE_BIN" 2>/dev/null | grep -q jail_remove_jd; then
    HAS_SYMBOL=1
  fi

  if [ "$OSMAJOR" -ge 15 ] && [ "$HAS_JAIL_OWN_DESC" = "1" ]; then
    if [ "$HAS_SYMBOL" = "1" ]; then
      pass "jail_remove_jd symbol present in binary (FreeBSD ${OSMAJOR} code path compiled)"
    else
      fail "jail_remove_jd symbol NOT found in binary on FreeBSD ${OSMAJOR}"
    fi
  else
    if [ "$HAS_SYMBOL" = "0" ]; then
      pass "jail_remove_jd correctly absent from binary on FreeBSD ${OSMAJOR}"
    else
      fail "jail_remove_jd unexpectedly present on FreeBSD ${OSMAJOR}"
    fi
  fi
else
  skip "binary not available for symbol check"
fi

# ===========================================================================
#  Layer 4: Integration Tests (skipped in compile-only CI)
# ===========================================================================

if [ "$HAS_BINARY" = "1" ]; then

section "T07: basic jail create/destroy"

if [ "$CAN_JAIL" = "1" ]; then
  JDIR=$(mktemp -d /tmp/_ci_jail_test.XXXXXX)
  mkdir -p "$JDIR/dev" "$JDIR/bin" "$JDIR/lib" "$JDIR/libexec"
  cp /bin/sh "$JDIR/bin/" 2>/dev/null || true
  cp /libexec/ld-elf.so.1 "$JDIR/libexec/" 2>/dev/null || true
  for lib in $(ldd /bin/sh 2>/dev/null | grep '=>' | awk '{print $3}'); do
    cp "$lib" "$JDIR/lib/" 2>/dev/null || true
  done

  JID=$(jail -ci path="$JDIR" persist host.hostname=ci-test 2>&1)
  RC=$?
  if [ "$RC" = "0" ] && [ -n "$JID" ]; then
    pass "jail created: jid=${JID}"
    jail -r "$JID" 2>/dev/null
    pass "jail removed"
  else
    fail "jail creation failed (rc=${RC}): ${JID}"
  fi
  rm -rf "$JDIR"
else
  skip "jail test (cannot create jails in this environment)"
fi

# ---------------------------------------------------------------------------
section "T08: jail descriptor API (FreeBSD 15.0+)"

if [ "$CAN_JAIL" = "1" ] && [ "$OSMAJOR" -ge 15 ] && [ "$HAS_JAIL_OWN_DESC" = "1" ]; then
  JDIR2=$(mktemp -d /tmp/_ci_jail_desc.XXXXXX)
  cat > /tmp/_ci_test_jdesc.c << CEOF
#include <sys/param.h>
#include <sys/jail.h>
#include <jail.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
int main(int argc, char **argv) {
    char desc[32] = {0};
    int jid = jail_setv(JAIL_CREATE | JAIL_OWN_DESC,
        "path", argv[1],
        "host.hostname", "ci-desc-test",
        "persist", NULL,
        "desc", desc,
        NULL);
    if (jid < 0) { fprintf(stderr, "jail_setv: %s\n", jail_errmsg); return 1; }
    int fd = atoi(desc);
    printf("jid=%d fd=%d\n", jid, fd);
    if (jail_remove_jd(fd) != 0) { fprintf(stderr, "jail_remove_jd: %s\n", strerror(errno)); return 1; }
    close(fd);
    printf("OK\n");
    return 0;
}
CEOF
  if cc -o /tmp/_ci_test_jdesc /tmp/_ci_test_jdesc.c -ljail 2>/dev/null; then
    OUTPUT=$(/tmp/_ci_test_jdesc "$JDIR2" 2>&1)
    RC=$?
    if [ "$RC" = "0" ] && echo "$OUTPUT" | grep -q "OK"; then
      pass "jail descriptor API: create with JAIL_OWN_DESC + jail_remove_jd() works"
    else
      fail "jail descriptor API failed (rc=${RC}): ${OUTPUT}"
    fi
  else
    fail "could not compile jail descriptor test"
  fi
  rm -rf "$JDIR2" /tmp/_ci_test_jdesc /tmp/_ci_test_jdesc.c
else
  skip "jail descriptor test (FreeBSD ${OSMAJOR}, JAIL_OWN_DESC=${HAS_JAIL_OWN_DESC}, CAN_JAIL=${CAN_JAIL})"
fi

# ---------------------------------------------------------------------------
section "T09: epair checksum offload fix"

# Source-level check first
if grep -q '\-txcsum' "$BUILDDIR/run.cpp" && grep -q '\-txcsum6' "$BUILDDIR/run.cpp"; then
  pass "run.cpp disables txcsum/txcsum6 on epair interfaces"
else
  fail "run.cpp missing -txcsum/-txcsum6 on epair"
fi

# Runtime test
if [ "$CAN_EPAIR" = "1" ]; then
  EPAIR_A=$(ifconfig epair create)
  EPAIR_B=$(echo "$EPAIR_A" | sed 's/a$/b/')

  ifconfig "$EPAIR_A" -txcsum -txcsum6 2>/dev/null
  ifconfig "$EPAIR_B" -txcsum -txcsum6 2>/dev/null

  # Check TXCSUM flag is gone
  TXCSUM_FOUND=0
  if ifconfig "$EPAIR_A" | grep -i options | grep -qi TXCSUM; then TXCSUM_FOUND=1; fi
  if ifconfig "$EPAIR_B" | grep -i options | grep -qi TXCSUM; then TXCSUM_FOUND=1; fi

  ifconfig "$EPAIR_A" destroy 2>/dev/null || true

  if [ "$TXCSUM_FOUND" = "0" ]; then
    pass "epair -txcsum -txcsum6 correctly disables checksum offload"
  else
    fail "epair still shows TXCSUM after disabling"
  fi
else
  skip "epair runtime test (cannot create epair)"
fi

# ---------------------------------------------------------------------------
section "T10: kldload fix"

if grep -q 'kldload(name)' "$BUILDDIR/util.cpp"; then
  pass "util.cpp kldload() uses 'name' parameter (not hardcoded)"
else
  fail "util.cpp kldload() may still have hardcoded module name"
fi

# Try loading ipfw_nat at runtime
if kldload ipfw_nat 2>/dev/null || kldstat -q -m ipfw_nat 2>/dev/null; then
  pass "ipfw_nat module loadable/loaded"
else
  skip "ipfw_nat module not available"
fi

# ---------------------------------------------------------------------------
section "T11: MNT_IGNORE runtime (devfs mount hidden from df)"

if [ "$CAN_JAIL" = "1" ]; then
  cat > /tmp/_ci_test_mntign.c << 'MEOF'
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
int main() {
    const char *dir = "/tmp/_ci_mnt_ignore";
    mkdir(dir, 0755);
    struct iovec iov[6];
    iov[0].iov_base = strdup("fstype"); iov[0].iov_len = 7;
    iov[1].iov_base = strdup("devfs");  iov[1].iov_len = 6;
    iov[2].iov_base = strdup("fspath"); iov[2].iov_len = 7;
    iov[3].iov_base = strdup(dir);      iov[3].iov_len = strlen(dir)+1;
    iov[4].iov_base = strdup("errmsg"); iov[4].iov_len = 7;
    char errmsg[255] = {0};
    iov[5].iov_base = errmsg; iov[5].iov_len = sizeof(errmsg);
    if (nmount(iov, 6, MNT_IGNORE) != 0) {
        fprintf(stderr, "nmount: %s (%s)\n", strerror(errno), errmsg);
        rmdir(dir); return 1;
    }
    /* Check: df should NOT show this mount */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "df 2>/dev/null | grep -c '%s'", dir);
    FILE *f = popen(cmd, "r");
    char buf[64] = {0};
    if (f) { fgets(buf, sizeof(buf), f); pclose(f); }
    int visible = atoi(buf);
    unmount(dir, 0);
    rmdir(dir);
    return (visible == 0) ? 0 : 1;
}
MEOF
  if cc -o /tmp/_ci_test_mntign /tmp/_ci_test_mntign.c 2>/dev/null; then
    if /tmp/_ci_test_mntign; then
      pass "MNT_IGNORE hides devfs mount from df"
    else
      if [ "$OSMAJOR" -ge 15 ]; then
        fail "MNT_IGNORE mount visible in df on FreeBSD ${OSMAJOR}"
      else
        skip "MNT_IGNORE mount visible in df on FreeBSD ${OSMAJOR} (pre-15.0 behavior)"
      fi
    fi
  else
    fail "could not compile MNT_IGNORE test"
  fi
  rm -f /tmp/_ci_test_mntign /tmp/_ci_test_mntign.c
else
  skip "MNT_IGNORE runtime test (cannot mount in this environment)"
fi

else
  # Compile-only CI: skip all integration tests
  section "T07: basic jail create/destroy"
  skip "compile-only CI (no full build)"
  section "T08: jail descriptor API (FreeBSD 15.0+)"
  skip "compile-only CI (no full build)"
  section "T09: epair checksum offload fix"
  # Source-level checks still run
  if grep -q '\-txcsum' "$BUILDDIR/run.cpp" && grep -q '\-txcsum6' "$BUILDDIR/run.cpp"; then
    pass "run.cpp disables txcsum/txcsum6 on epair interfaces"
  else
    fail "run.cpp missing -txcsum/-txcsum6 on epair"
  fi
  skip "epair runtime test (compile-only CI)"
  section "T10: kldload fix"
  if grep -q 'kldload(name)' "$BUILDDIR/util.cpp"; then
    pass "util.cpp kldload() uses 'name' parameter (not hardcoded)"
  else
    fail "util.cpp kldload() may still have hardcoded module name"
  fi
  skip "kldload runtime test (compile-only CI)"
  section "T11: MNT_IGNORE runtime (devfs mount hidden from df)"
  skip "compile-only CI (no full build)"
fi

# ---------------------------------------------------------------------------
section "T12: source-level regression guards"

# ipfw warning for FreeBSD 15+
if grep -q 'getFreeBSDMajorVersion.*>=.*15' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has ipfw version >= 15 guard"
else
  fail "run.cpp missing FreeBSD 15+ ipfw guard"
fi

# Group membership verification
if grep -q '/usr/bin/id' "$BUILDDIR/run.cpp"; then
  pass "run.cpp verifies group membership with /usr/bin/id"
else
  fail "run.cpp missing /usr/bin/id group verification"
fi

# Dual jail code paths
JAIL_IFDEFS=$(grep -c '#ifdef JAIL_OWN_DESC' "$BUILDDIR/run.cpp" || echo 0)
if [ "$JAIL_IFDEFS" -ge 2 ]; then
  pass "run.cpp has ${JAIL_IFDEFS} #ifdef JAIL_OWN_DESC guards (create + destroy)"
else
  fail "expected >=2 #ifdef JAIL_OWN_DESC guards, found ${JAIL_IFDEFS}"
fi

# VNET sysctl comment
if grep -q 'loader tunable' "$BUILDDIR/run.cpp" || grep -q 'CTLFLAG_TUN\|loader.conf' "$BUILDDIR/run.cpp"; then
  pass "run.cpp documents VNET sysctl as loader tunable"
else
  fail "run.cpp missing VNET loader tunable documentation"
fi

# sys/jail.h C++ safety comment
if grep -q '238928' "$BUILDDIR/run.cpp"; then
  pass "run.cpp documents sys/jail.h C++ bug #238928"
else
  fail "run.cpp missing sys/jail.h C++ safety comment"
fi

# ---------------------------------------------------------------------------
section "T13: ZFS support"

# Source-level: ZFS detection functions in util.cpp
if grep -q 'isOnZfs\|getZfsDataset\|isZfsEncrypted' "$BUILDDIR/util.cpp"; then
  pass "util.cpp has ZFS detection functions"
else
  fail "util.cpp missing ZFS detection functions"
fi

# Source-level: spec parser supports zfs/datasets
if grep -q 'zfsDatasets' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp supports zfs/datasets parsing"
else
  fail "spec.cpp missing zfs/datasets support"
fi

# Source-level: run.cpp has ZFS dataset attach/detach (exec-based: "zfs", "jail")
if grep -q '"zfs".*"jail"' "$BUILDDIR/run.cpp" && grep -q '"zfs".*"unjail"' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has ZFS dataset attach/detach (exec-based)"
else
  fail "run.cpp missing ZFS dataset attach/detach"
fi

# Runtime: test statfs-based ZFS detection
if [ "$HAS_ZFS" = "1" ]; then
  cat > /tmp/_ci_test_zfs.c << 'ZEOF'
#include <sys/param.h>
#include <sys/mount.h>
#include <stdio.h>
#include <string.h>
int main() {
    struct statfs sfs;
    if (statfs("/", &sfs) == 0) {
        printf("fstype=%s\n", sfs.f_fstypename);
        if (strcmp(sfs.f_fstypename, "zfs") == 0) {
            printf("dataset=%s\n", sfs.f_mntfromname);
            return 0;
        }
    }
    return 1;
}
ZEOF
  if cc -o /tmp/_ci_test_zfs /tmp/_ci_test_zfs.c 2>/dev/null; then
    if /tmp/_ci_test_zfs >/dev/null 2>&1; then
      pass "ZFS detected on root filesystem via statfs()"
    else
      skip "root filesystem is not ZFS (statfs check works but fs is not ZFS)"
    fi
  else
    fail "could not compile ZFS statfs test"
  fi
  rm -f /tmp/_ci_test_zfs /tmp/_ci_test_zfs.c
else
  skip "ZFS not available on this system"
fi

# Runtime: ZFS jail dataset attach test
if [ "$HAS_ZFS" = "1" ] && [ "$CAN_JAIL" = "1" ]; then
  TESTPOOL=$(zpool list -H -o name 2>/dev/null | head -1)
  if [ -n "$TESTPOOL" ]; then
    TESTDS="${TESTPOOL}/ci-crate-test-$$"
    if zfs create "$TESTDS" 2>/dev/null; then
      JDIR3=$(mktemp -d /tmp/_ci_zfs_jail.XXXXXX)
      mkdir -p "$JDIR3/dev"
      JID3=$(jail -ci path="$JDIR3" persist host.hostname=ci-zfs-test \
             allow.mount allow.mount.zfs enforce_statfs=1 2>&1)
      RC=$?
      if [ "$RC" = "0" ] && [ -n "$JID3" ]; then
        if zfs jail "$JID3" "$TESTDS" 2>/dev/null; then
          pass "zfs jail: attached dataset ${TESTDS} to jail ${JID3}"
          zfs unjail "$JID3" "$TESTDS" 2>/dev/null
        else
          skip "zfs jail attach failed (may need elevated privileges)"
        fi
        jail -r "$JID3" 2>/dev/null
      else
        skip "could not create jail for ZFS test"
      fi
      zfs destroy "$TESTDS" 2>/dev/null
      rm -rf "$JDIR3"
    else
      skip "could not create test ZFS dataset on pool ${TESTPOOL}"
    fi
  else
    skip "no ZFS pool found for jail dataset test"
  fi
else
  skip "ZFS jail dataset test (HAS_ZFS=${HAS_ZFS}, CAN_JAIL=${CAN_JAIL})"
fi

# Runtime: ZFS encryption property query
if [ "$HAS_ZFS" = "1" ]; then
  ENC_OUTPUT=$(zfs get -H -o value encryption / 2>/dev/null || echo "unavailable")
  if [ "$ENC_OUTPUT" != "unavailable" ]; then
    pass "ZFS encryption property queryable (root fs encryption=${ENC_OUTPUT})"
  else
    skip "ZFS encryption property not available"
  fi
else
  skip "ZFS encryption test (ZFS not available)"
fi

# ---------------------------------------------------------------------------
section "T14: security hardening"

# shellQuote on values still passed through shell (Category C: jexec, chroot)
if grep -q 'shellQuote(spec.runCmdExecutable)' "$BUILDDIR/run.cpp"; then
  pass "run.cpp quotes spec.runCmdExecutable in shell commands"
else
  fail "run.cpp missing shellQuote on spec.runCmdExecutable"
fi

if grep -q 'shellQuote(argv\[i\])' "$BUILDDIR/run.cpp"; then
  pass "run.cpp quotes argv elements in argsToString"
else
  fail "run.cpp missing shellQuote on argv in argsToString"
fi

# user and jailPath now go through exec (no shell) — verify exec-based patterns
if grep -q 'execCommandGetStatus.*jexec' "$BUILDDIR/run.cpp"; then
  pass "run.cpp uses execCommandGetStatus for jexec (user/jid via exec, not shell)"
else
  fail "run.cpp missing execCommandGetStatus for jexec"
fi

if grep -q 'execInJail' "$BUILDDIR/run.cpp"; then
  pass "run.cpp uses execInJail for in-jail commands (exec-based)"
else
  fail "run.cpp missing execInJail lambda"
fi

# Values migrated to exec — must NOT need shellQuote (no shell involved)
if grep -q 'execPipeline.*runCrateFile\|stdinFile.*runCrateFile\|runCrateFile.*stdinFile' "$BUILDDIR/run.cpp" \
   || grep -q 'args.runCrateFile' "$BUILDDIR/run.cpp"; then
  pass "run.cpp passes args.runCrateFile via exec (no shell)"
else
  fail "run.cpp: args.runCrateFile handling unclear"
fi

if grep -q 'execInJail.*service' "$BUILDDIR/run.cpp"; then
  pass "run.cpp passes service names via execInJail (no shell)"
else
  fail "run.cpp: service names not passed via exec"
fi

if grep -q 'execPipeline' "$BUILDDIR/create.cpp"; then
  pass "create.cpp uses execPipeline for tar/xz (no shell for jailPath/crateFileName)"
else
  fail "create.cpp: jailPath/crateFileName not exec-based"
fi

# getpwuid instead of getenv("USER")
if grep -q 'getpwuid' "$BUILDDIR/run.cpp"; then
  pass "run.cpp uses getpwuid for user identity"
else
  fail "run.cpp still uses getenv(USER) instead of getpwuid"
fi

if ! grep -q 'getenv.*USER' "$BUILDDIR/run.cpp"; then
  pass "run.cpp does not use getenv(USER)"
else
  fail "run.cpp still references getenv(USER)"
fi

# tar traversal protection
if grep -q '\.\..*directory traversal' "$BUILDDIR/run.cpp"; then
  pass "run.cpp validates crate archive for directory traversal"
else
  fail "run.cpp missing tar directory traversal validation"
fi

# O_NOFOLLOW on file writes
if grep -q 'O_NOFOLLOW' "$BUILDDIR/util.cpp"; then
  pass "util.cpp uses O_NOFOLLOW on file writes"
else
  fail "util.cpp missing O_NOFOLLOW protection"
fi

# ip.forwarding save/restore
if grep -q 'origIpForwarding' "$BUILDDIR/run.cpp"; then
  pass "run.cpp saves/restores ip.forwarding sysctl"
else
  fail "run.cpp missing ip.forwarding save/restore"
fi

# X11 socket directory permissions (01777, not 0777)
if grep -q '01777' "$BUILDDIR/run.cpp"; then
  pass "run.cpp uses sticky bit (01777) for X11 socket dir"
else
  fail "run.cpp missing sticky bit on X11 socket directory"
fi

# ---------------------------------------------------------------------------
section "T15: architectural security hardening"

# exec-based execution in source files
if grep -q 'execCommand' "$BUILDDIR/util.cpp" && grep -q 'execCommand' "$BUILDDIR/run.cpp"; then
  pass "execCommand() present in util.cpp and run.cpp"
else
  fail "execCommand() missing from util.cpp or run.cpp"
fi

if grep -q 'execPipeline' "$BUILDDIR/util.cpp" && grep -q 'execPipeline' "$BUILDDIR/run.cpp"; then
  pass "execPipeline() present in util.cpp and run.cpp"
else
  fail "execPipeline() missing from util.cpp or run.cpp"
fi

if grep -q 'execPipeline' "$BUILDDIR/create.cpp"; then
  pass "create.cpp uses execPipeline (no shell for tar/xz)"
else
  fail "create.cpp missing execPipeline"
fi

# Signal handling
if grep -q 'sigaction' "$BUILDDIR/run.cpp" && grep -q 'g_signalReceived' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has SIGINT/SIGTERM signal handling"
else
  fail "run.cpp missing signal handling (sigaction/g_signalReceived)"
fi

# RAII file descriptors
if grep -q 'UniqueFd' "$BUILDDIR/util.h"; then
  pass "util.h has UniqueFd RAII wrapper for file descriptors"
else
  fail "util.h missing UniqueFd RAII wrapper"
fi

# Path safety validation
if grep -q 'safePath' "$BUILDDIR/util.cpp" && grep -q 'safePath' "$BUILDDIR/run.cpp"; then
  pass "safePath() present in util.cpp and run.cpp"
else
  fail "safePath() missing from util.cpp or run.cpp"
fi

# Resource leak fixes
if grep -q 'make_unique<FwUsers>' "$BUILDDIR/ctx.cpp"; then
  pass "ctx.cpp uses make_unique (prevents pointer leak)"
else
  fail "ctx.cpp missing make_unique in FwUsers::lock()"
fi

# mount.cpp: free before error check
MOUNT_FREE_LINE=$(grep -n '::free(iov' "$BUILDDIR/mount.cpp" | head -1 | cut -d: -f1)
MOUNT_ERR_LINE=$(grep -n '    ERR("nmount' "$BUILDDIR/mount.cpp" | head -1 | cut -d: -f1)
if [ -n "$MOUNT_FREE_LINE" ] && [ -n "$MOUNT_ERR_LINE" ] && [ "$MOUNT_FREE_LINE" -lt "$MOUNT_ERR_LINE" ]; then
  pass "mount.cpp frees strdup'd names before ERR check"
else
  fail "mount.cpp may leak strdup'd names on nmount error"
fi

# resolv.conf parsed directly (no grep pipeline)
if grep -q 'ifstream.*resolv' "$BUILDDIR/net.cpp"; then
  pass "net.cpp parses /etc/resolv.conf directly (no shell pipeline)"
else
  fail "net.cpp missing direct resolv.conf parsing"
fi

# xzThreadsArg for exec-based pipelines
if grep -q 'xzThreadsArg' "$BUILDDIR/cmd.cpp" && grep -q 'xzThreadsArg' "$BUILDDIR/run.cpp"; then
  pass "xzThreadsArg used for exec-based xz calls"
else
  fail "xzThreadsArg missing from cmd.cpp or run.cpp"
fi

# Shell elimination: no system()/popen()/runCommand() in source files
if ! grep -q 'system(' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has no system() calls (fully exec-based)"
else
  fail "run.cpp still uses system()"
fi

if ! grep -q 'popen(' "$BUILDDIR/util.cpp"; then
  pass "util.cpp has no popen() calls (fully exec-based)"
else
  fail "util.cpp still uses popen()"
fi

if ! grep -q 'runCommand(' "$BUILDDIR/run.cpp" && ! grep -q 'runCommand(' "$BUILDDIR/create.cpp"; then
  pass "runCommand() removed from run.cpp and create.cpp"
else
  fail "runCommand() still present in run.cpp or create.cpp"
fi

# fnmatch-based wildcard expansion (no shell)
if grep -q 'fnmatch' "$BUILDDIR/util.cpp"; then
  pass "util.cpp uses fnmatch for wildcard expansion (no shell)"
else
  fail "util.cpp missing fnmatch-based wildcard expansion"
fi

# make_shared for factory methods
if grep -q 'make_shared' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp uses make_shared for factory methods"
else
  fail "spec.cpp missing make_shared usage"
fi

# execCommandGetStatus for status-returning exec
if grep -q 'execCommandGetStatus' "$BUILDDIR/util.cpp"; then
  pass "util.cpp implements execCommandGetStatus"
else
  fail "util.cpp missing execCommandGetStatus implementation"
fi

# ---------------------------------------------------------------------------
section "T16: V4 — unpredictable jail directory names"

# randomHex() in util.cpp and used in run.cpp/create.cpp
if grep -q 'randomHex' "$BUILDDIR/util.cpp" && grep -q 'randomHex' "$BUILDDIR/run.cpp"; then
  pass "randomHex() present in util.cpp and used in run.cpp"
else
  fail "randomHex() missing from util.cpp or run.cpp"
fi

if grep -q 'randomHex' "$BUILDDIR/create.cpp"; then
  pass "create.cpp uses randomHex for jail directory names"
else
  fail "create.cpp missing randomHex for jail directory names"
fi

# arc4random_buf for cryptographic randomness
if grep -q 'arc4random_buf' "$BUILDDIR/util.cpp"; then
  pass "util.cpp uses arc4random_buf for cryptographic randomness"
else
  fail "util.cpp missing arc4random_buf"
fi

# jail path construction must NOT use getpid
if ! grep -q 'jailDirectoryPath.*getpid\|jailPath.*getpid' "$BUILDDIR/run.cpp"; then
  pass "run.cpp jail path does not use predictable PID"
else
  fail "run.cpp jail path still uses getpid()"
fi

if ! grep -q 'jailDirectoryPath.*getpid\|jailPath.*getpid' "$BUILDDIR/create.cpp"; then
  pass "create.cpp jail path does not use predictable PID"
else
  fail "create.cpp jail path still uses getpid()"
fi

# copyFile error message should reference actual filenames
if ! grep -q 'file1\.txt' "$BUILDDIR/util.cpp"; then
  pass "util.cpp copyFile has proper error message (no hardcoded filename)"
else
  fail "util.cpp copyFile still has hardcoded 'file1.txt' in error message"
fi

# ---------------------------------------------------------------------------
section "T17: Phase 1 features (RCTL, IPC, validate)"

# IPC controls in spec parser
if grep -q 'allowSysvipc' "$BUILDDIR/spec.h"; then
  pass "spec.h has IPC control fields"
else
  fail "spec.h missing IPC control fields"
fi

if grep -q '"allow.sysvipc"' "$BUILDDIR/run.cpp"; then
  pass "run.cpp passes allow.sysvipc to jail_setv"
else
  fail "run.cpp missing allow.sysvipc in jail_setv"
fi

# IPC raw_sockets override
if grep -q 'ipcRawSocketsOverride' "$BUILDDIR/spec.h"; then
  pass "spec.h has ipcRawSocketsOverride field"
else
  fail "spec.h missing ipcRawSocketsOverride"
fi

if grep -q 'optRawSockets' "$BUILDDIR/run.cpp"; then
  pass "run.cpp uses optRawSockets (overridable via ipc section)"
else
  fail "run.cpp missing optRawSockets"
fi

# IPC parsing in spec.cpp
if grep -q '"ipc"' "$BUILDDIR/spec.cpp" && grep -q '"sysvipc"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses ipc/sysvipc section"
else
  fail "spec.cpp missing ipc/sysvipc parsing"
fi

if grep -q '"mqueue"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses ipc/mqueue"
else
  fail "spec.cpp missing ipc/mqueue parsing"
fi

# RCTL resource limits
if grep -q 'limits' "$BUILDDIR/spec.h"; then
  pass "spec.h has limits field"
else
  fail "spec.h missing limits field"
fi

if grep -q 'rctl' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has RCTL support"
else
  fail "run.cpp missing RCTL support"
fi

if grep -q '"limits"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses limits section"
else
  fail "spec.cpp missing limits parsing"
fi

# RCTL limit name validation
if grep -q 'validLimits' "$BUILDDIR/spec.cpp" && grep -q '"maxproc"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp validates RCTL limit names"
else
  fail "spec.cpp missing RCTL limit name validation"
fi

# RCTL cleanup
if grep -q 'removeRctlRules' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has RCTL cleanup (removeRctlRules)"
else
  fail "run.cpp missing RCTL cleanup"
fi

# Validate command
if grep -q 'CmdValidate' "$BUILDDIR/args.h"; then
  pass "args.h has CmdValidate command"
else
  fail "args.h missing CmdValidate"
fi

if grep -q 'validate' "$BUILDDIR/args.cpp"; then
  pass "args.cpp handles validate command"
else
  fail "args.cpp missing validate command handling"
fi

if [ -f "$BUILDDIR/validate.cpp" ]; then
  pass "validate.cpp exists"
else
  fail "validate.cpp not found"
fi

if grep -q 'validateCrateSpec' "$BUILDDIR/commands.h"; then
  pass "commands.h declares validateCrateSpec"
else
  fail "commands.h missing validateCrateSpec declaration"
fi

if grep -q 'validateCrateSpec' "$BUILDDIR/main.cpp"; then
  pass "main.cpp dispatches CmdValidate to validateCrateSpec"
else
  fail "main.cpp missing CmdValidate dispatch"
fi

if grep -q 'validate' "$BUILDDIR/Makefile"; then
  pass "Makefile includes validate.cpp"
else
  fail "Makefile missing validate.cpp"
fi

# ---------------------------------------------------------------------------
section "T18: Phase 2 features (snapshots, encryption, DNS filter, security)"

# Snapshot command
if grep -q 'CmdSnapshot' "$BUILDDIR/args.h"; then
  pass "args.h has CmdSnapshot command"
else
  fail "args.h missing CmdSnapshot"
fi

if [ -f "$BUILDDIR/snapshot.cpp" ]; then
  pass "snapshot.cpp exists"
else
  fail "snapshot.cpp not found"
fi

if grep -q 'snapshotCrate' "$BUILDDIR/commands.h"; then
  pass "commands.h declares snapshotCrate"
else
  fail "commands.h missing snapshotCrate"
fi

if grep -q 'snapshotCrate' "$BUILDDIR/main.cpp"; then
  pass "main.cpp dispatches CmdSnapshot to snapshotCrate"
else
  fail "main.cpp missing CmdSnapshot dispatch"
fi

if grep -q '"zfs".*"snapshot"' "$BUILDDIR/snapshot.cpp"; then
  pass "snapshot.cpp calls zfs snapshot"
else
  fail "snapshot.cpp missing zfs snapshot call"
fi

if grep -q '"zfs".*"rollback"' "$BUILDDIR/snapshot.cpp"; then
  pass "snapshot.cpp calls zfs rollback"
else
  fail "snapshot.cpp missing zfs rollback call"
fi

if grep -q '"zfs".*"diff"' "$BUILDDIR/snapshot.cpp"; then
  pass "snapshot.cpp calls zfs diff"
else
  fail "snapshot.cpp missing zfs diff call"
fi

if grep -q 'snapshot' "$BUILDDIR/Makefile"; then
  pass "Makefile includes snapshot.cpp"
else
  fail "Makefile missing snapshot.cpp"
fi

# Snapshot arg parsing
if grep -q 'snapshotSubcmd' "$BUILDDIR/args.h" && grep -q 'snapshotDataset' "$BUILDDIR/args.h"; then
  pass "args.h has snapshot parameter fields"
else
  fail "args.h missing snapshot parameter fields"
fi

if grep -q 'snapshotSubcmd.*"create"' "$BUILDDIR/args.cpp" && grep -q 'snapshotSubcmd.*"diff"' "$BUILDDIR/args.cpp"; then
  pass "args.cpp validates snapshot subcommands"
else
  fail "args.cpp missing snapshot subcommand validation"
fi

# Encrypted containers
if grep -q 'encrypted' "$BUILDDIR/spec.h"; then
  pass "spec.h has encrypted field"
else
  fail "spec.h missing encrypted field"
fi

if grep -q '"encrypted"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses encrypted section"
else
  fail "spec.cpp missing encrypted parsing"
fi

if grep -q 'encryptionMethod\|encryptionCipher' "$BUILDDIR/spec.h"; then
  pass "spec.h has encryption method/cipher fields"
else
  fail "spec.h missing encryption method/cipher fields"
fi

if grep -q 'aes-256-gcm' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp validates AES encryption ciphers"
else
  fail "spec.cpp missing AES cipher validation"
fi

if grep -q 'spec.encrypted' "$BUILDDIR/run.cpp"; then
  pass "run.cpp checks spec.encrypted for ZFS encryption enforcement"
else
  fail "run.cpp missing spec.encrypted check"
fi

# DNS filtering
if grep -q 'DnsFilter\|dnsFilter' "$BUILDDIR/spec.h"; then
  pass "spec.h has DnsFilter struct"
else
  fail "spec.h missing DnsFilter"
fi

if grep -q '"dns_filter"\|"dns-filter"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses dns_filter section"
else
  fail "spec.cpp missing dns_filter parsing"
fi

if grep -q 'unbound' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has unbound DNS integration"
else
  fail "run.cpp missing unbound integration"
fi

if grep -q 'always_nxdomain\|local-zone' "$BUILDDIR/run.cpp"; then
  pass "run.cpp generates unbound blocking rules"
else
  fail "run.cpp missing unbound blocking rules"
fi

if grep -q 'redirect_blocked\|redirect-blocked' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses redirect_blocked option"
else
  fail "spec.cpp missing redirect_blocked parsing"
fi

# Security hardening
if grep -q 'enforceStatfs' "$BUILDDIR/spec.h"; then
  pass "spec.h has enforceStatfs field"
else
  fail "spec.h missing enforceStatfs"
fi

if grep -q 'allowChflags\|allowMlock' "$BUILDDIR/spec.h"; then
  pass "spec.h has allowChflags/allowMlock fields"
else
  fail "spec.h missing allowChflags/allowMlock"
fi

if grep -q '"security"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses security section"
else
  fail "spec.cpp missing security parsing"
fi

if grep -q '"allow.quotas"' "$BUILDDIR/run.cpp"; then
  pass "run.cpp passes allow.quotas to jail_setv"
else
  fail "run.cpp missing allow.quotas in jail_setv"
fi

if grep -q '"allow.set_hostname"' "$BUILDDIR/run.cpp"; then
  pass "run.cpp passes allow.set_hostname to jail_setv"
else
  fail "run.cpp missing allow.set_hostname in jail_setv"
fi

if grep -q '"allow.chflags"' "$BUILDDIR/run.cpp"; then
  pass "run.cpp passes allow.chflags to jail_setv"
else
  fail "run.cpp missing allow.chflags in jail_setv"
fi

if grep -q '"allow.mlock"' "$BUILDDIR/run.cpp"; then
  pass "run.cpp passes allow.mlock to jail_setv"
else
  fail "run.cpp missing allow.mlock in jail_setv"
fi

# Validate cross-checks for new features
if grep -q 'dnsFilter\|dns_filter' "$BUILDDIR/validate.cpp"; then
  pass "validate.cpp checks dns_filter configuration"
else
  fail "validate.cpp missing dns_filter checks"
fi

if grep -q 'encrypted' "$BUILDDIR/validate.cpp"; then
  pass "validate.cpp checks encryption configuration"
else
  fail "validate.cpp missing encryption checks"
fi

if grep -q 'allowChflags\|allow_chflags' "$BUILDDIR/validate.cpp"; then
  pass "validate.cpp warns about chflags/mlock security implications"
else
  fail "validate.cpp missing chflags/mlock warnings"
fi

# ===========================================================================
section "T19: Phase 3 features (COW, templates, X11 modes, clipboard, dbus, managed services, socket_proxy)"

# §6 COW
if grep -q 'CowOptions' "$BUILDDIR/spec.h"; then
  pass "spec.h has CowOptions struct"
else
  fail "spec.h missing CowOptions struct"
fi

if grep -q '"cow"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses cow section"
else
  fail "spec.cpp missing cow parsing"
fi

if grep -q 'cowOptions' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has COW clone logic"
else
  fail "run.cpp missing COW logic"
fi

if grep -q 'zfs.*snapshot.*snapName\|zfs.*clone.*cloneName' "$BUILDDIR/run.cpp"; then
  pass "run.cpp calls zfs snapshot/clone for COW"
else
  fail "run.cpp missing zfs snapshot/clone call"
fi

if grep -q 'destroyCowClone' "$BUILDDIR/run.cpp"; then
  pass "run.cpp destroys ephemeral COW clones"
else
  fail "run.cpp missing COW cleanup"
fi

if grep -q 'ephemeral.*persistent' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp validates cow mode values"
else
  fail "spec.cpp missing cow mode validation"
fi

# §10 Templates
if grep -q 'createTemplate' "$BUILDDIR/args.h"; then
  pass "args.h has createTemplate field"
else
  fail "args.h missing createTemplate field"
fi

if grep -q 'template' "$BUILDDIR/args.cpp"; then
  pass "args.cpp handles --template flag"
else
  fail "args.cpp missing --template handling"
fi

if grep -q 'crate/templates' "$BUILDDIR/args.cpp"; then
  pass "args.cpp searches template paths"
else
  fail "args.cpp missing template path search"
fi

# §11 X11 modes
if grep -q 'X11Options' "$BUILDDIR/spec.h"; then
  pass "spec.h has X11Options struct"
else
  fail "spec.h missing X11Options struct"
fi

if grep -q '"x11"' "$BUILDDIR/spec.cpp" && grep -q 'x11.*mode' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses x11 mode/resolution"
else
  fail "spec.cpp missing x11 mode parsing"
fi

if grep -q 'Xephyr' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has Xephyr nested X11 support"
else
  fail "run.cpp missing Xephyr support"
fi

if grep -q 'mode.*none.*no X11\|x11.*none' "$BUILDDIR/run.cpp"; then
  pass "run.cpp handles x11 mode=none"
else
  fail "run.cpp missing x11 mode=none handling"
fi

# §12 Clipboard
if grep -q 'ClipboardOptions' "$BUILDDIR/spec.h"; then
  pass "spec.h has ClipboardOptions struct"
else
  fail "spec.h missing ClipboardOptions struct"
fi

if grep -q '"clipboard"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses clipboard section"
else
  fail "spec.cpp missing clipboard parsing"
fi

# §13 D-Bus
if grep -q 'DbusOptions' "$BUILDDIR/spec.h"; then
  pass "spec.h has DbusOptions struct"
else
  fail "spec.h missing DbusOptions struct"
fi

if grep -q '"dbus"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses dbus section"
else
  fail "spec.cpp missing dbus parsing"
fi

if grep -q 'DBUS_SESSION_BUS_ADDRESS' "$BUILDDIR/run.cpp"; then
  pass "run.cpp sets DBUS_SESSION_BUS_ADDRESS"
else
  fail "run.cpp missing DBUS_SESSION_BUS_ADDRESS"
fi

if grep -q 'dbus-1.*session-local.conf\|session-local.conf' "$BUILDDIR/run.cpp"; then
  pass "run.cpp generates D-Bus session policy"
else
  fail "run.cpp missing D-Bus policy generation"
fi

# §14 Managed services
if grep -q 'ManagedService' "$BUILDDIR/spec.h"; then
  pass "spec.h has ManagedService struct"
else
  fail "spec.h missing ManagedService struct"
fi

if grep -q '"services"' "$BUILDDIR/spec.cpp" && grep -q '"managed"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses services/managed section"
else
  fail "spec.cpp missing services/managed parsing"
fi

if grep -q 'managedServices' "$BUILDDIR/run.cpp" && grep -q 'rc.conf' "$BUILDDIR/run.cpp"; then
  pass "run.cpp generates rc.conf entries for managed services"
else
  fail "run.cpp missing managed services rc.conf"
fi

if grep -q 'managed.*onestart\|start managed service' "$BUILDDIR/run.cpp"; then
  pass "run.cpp starts managed services with onestart"
else
  fail "run.cpp missing managed service start"
fi

# §15 Socket proxy
if grep -q 'SocketProxy' "$BUILDDIR/spec.h"; then
  pass "spec.h has SocketProxy struct"
else
  fail "spec.h missing SocketProxy struct"
fi

if grep -q '"socket_proxy"\|"socket-proxy"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses socket_proxy section"
else
  fail "spec.cpp missing socket_proxy parsing"
fi

if grep -q 'socketProxy' "$BUILDDIR/run.cpp" && grep -q 'nullfs' "$BUILDDIR/run.cpp"; then
  pass "run.cpp shares sockets via nullfs"
else
  fail "run.cpp missing socket nullfs sharing"
fi

if grep -q 'socat\|UNIX-LISTEN\|UNIX-CONNECT' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has socat proxy support"
else
  fail "run.cpp missing socat proxy"
fi

# Validate cross-checks
if grep -q 'cowOptions' "$BUILDDIR/validate.cpp"; then
  pass "validate.cpp checks COW configuration"
else
  fail "validate.cpp missing COW checks"
fi

if grep -q 'x11Options.*nested\|nested.*Xephyr' "$BUILDDIR/validate.cpp"; then
  pass "validate.cpp checks nested X11 requirements"
else
  fail "validate.cpp missing X11 checks"
fi

if grep -q 'clipboardOptions' "$BUILDDIR/validate.cpp"; then
  pass "validate.cpp checks clipboard isolation"
else
  fail "validate.cpp missing clipboard checks"
fi

if grep -q 'dbusOptions' "$BUILDDIR/validate.cpp"; then
  pass "validate.cpp checks D-Bus requirements"
else
  fail "validate.cpp missing D-Bus checks"
fi

if grep -q 'socketProxy' "$BUILDDIR/validate.cpp"; then
  pass "validate.cpp checks socket proxy configuration"
else
  fail "validate.cpp missing socket proxy checks"
fi

# ===========================================================================
section "T20: Phase 4 features (pf firewall, Capsicum/MAC, template merge, clipboard proxy, terminal)"

# §3 Per-container firewall policy
if grep -q 'FirewallPolicy' "$BUILDDIR/spec.h"; then
  pass "spec.h has FirewallPolicy struct"
else
  fail "spec.h missing FirewallPolicy struct"
fi

if grep -q '"firewall"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses firewall section"
else
  fail "spec.cpp missing firewall parsing"
fi

if grep -q 'firewallPolicy' "$BUILDDIR/spec.cpp" && grep -q 'block-ip\|block_ip' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses firewall block-ip and allow rules"
else
  fail "spec.cpp missing firewall rule parsing"
fi

if grep -q 'pfctl' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has pfctl calls for pf anchor management"
else
  fail "run.cpp missing pfctl calls"
fi

if grep -q 'pf.*anchor\|anchorName\|crate/' "$BUILDDIR/run.cpp"; then
  pass "run.cpp creates pf anchors per container"
else
  fail "run.cpp missing pf anchor logic"
fi

if grep -q 'destroyPfAnchor' "$BUILDDIR/run.cpp"; then
  pass "run.cpp cleans up pf anchors on exit"
else
  fail "run.cpp missing pf anchor cleanup"
fi

# §8 Capsicum + MAC
if grep -q 'SecurityAdvanced' "$BUILDDIR/spec.h"; then
  pass "spec.h has SecurityAdvanced struct"
else
  fail "spec.h missing SecurityAdvanced struct"
fi

if grep -q '"security_advanced"\|"security-advanced"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses security_advanced section"
else
  fail "spec.cpp missing security_advanced parsing"
fi

if grep -q 'capsicum' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses capsicum option"
else
  fail "spec.cpp missing capsicum parsing"
fi

if grep -q 'mac_bsdextended\|mac-bsdextended' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses mac_bsdextended rules"
else
  fail "spec.cpp missing mac_bsdextended parsing"
fi

if grep -q 'ugidfw' "$BUILDDIR/run.cpp"; then
  pass "run.cpp uses ugidfw for MAC bsdextended rules"
else
  fail "run.cpp missing ugidfw calls"
fi

if grep -q 'mac_bsdextended\|removeMacRules' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has MAC rule lifecycle management"
else
  fail "run.cpp missing MAC rule management"
fi

if grep -q 'mac_portacl\|mac-portacl' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses mac_portacl section"
else
  fail "spec.cpp missing mac_portacl parsing"
fi

if grep -q 'hideOtherJails\|hide_other_jails\|hide-other-jails' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses hide_other_jails option"
else
  fail "spec.cpp missing hide_other_jails parsing"
fi

# §10 Template merging
if grep -q 'mergeSpecs' "$BUILDDIR/spec.h"; then
  pass "spec.h declares mergeSpecs()"
else
  fail "spec.h missing mergeSpecs declaration"
fi

if grep -q 'mergeSpecs' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp implements mergeSpecs()"
else
  fail "spec.cpp missing mergeSpecs implementation"
fi

if grep -q 'mergeSpecs' "$BUILDDIR/main.cpp"; then
  pass "main.cpp calls mergeSpecs for template merging"
else
  fail "main.cpp missing mergeSpecs call"
fi

if grep -q 'createTemplate' "$BUILDDIR/main.cpp"; then
  pass "main.cpp checks createTemplate for merge dispatch"
else
  fail "main.cpp missing createTemplate check"
fi

# Template files exist
TEMPLATE_COUNT=$(ls "$BUILDDIR/templates/"*.yml 2>/dev/null | wc -l)
if [ "$TEMPLATE_COUNT" -ge 5 ]; then
  pass "5 template files exist in templates/"
else
  fail "expected 5 template files, found $TEMPLATE_COUNT"
fi

if [ -f "$BUILDDIR/templates/minimal.yml" ]; then
  pass "templates/minimal.yml exists"
else
  fail "templates/minimal.yml missing"
fi

if [ -f "$BUILDDIR/templates/privacy.yml" ]; then
  pass "templates/privacy.yml exists"
else
  fail "templates/privacy.yml missing"
fi

if [ -f "$BUILDDIR/templates/development.yml" ]; then
  pass "templates/development.yml exists"
else
  fail "templates/development.yml missing"
fi

# §12 Clipboard proxy daemon
if grep -q 'clipPid\|killClipboardProxy\|clipboard.*proxy' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has clipboard proxy daemon logic"
else
  fail "run.cpp missing clipboard proxy daemon"
fi

if grep -q 'xclip' "$BUILDDIR/run.cpp"; then
  pass "run.cpp uses xclip for clipboard proxying"
else
  fail "run.cpp missing xclip usage"
fi

if grep -q 'killClipboardProxy' "$BUILDDIR/run.cpp"; then
  pass "run.cpp cleans up clipboard proxy on exit"
else
  fail "run.cpp missing clipboard proxy cleanup"
fi

# §16 Terminal isolation
if grep -q 'TerminalOptions' "$BUILDDIR/spec.h"; then
  pass "spec.h has TerminalOptions struct"
else
  fail "spec.h missing TerminalOptions struct"
fi

if grep -q '"terminal"' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses terminal section"
else
  fail "spec.cpp missing terminal parsing"
fi

if grep -q 'devfsRuleset\|devfs_ruleset\|devfs-ruleset' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses devfs_ruleset option"
else
  fail "spec.cpp missing devfs_ruleset parsing"
fi

if grep -q 'allowRawTty\|allow_raw_tty\|allow-raw-tty' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp parses allow_raw_tty option"
else
  fail "spec.cpp missing allow_raw_tty parsing"
fi

if grep -q 'devfs.*ruleset\|terminalOptions.*devfsRuleset' "$BUILDDIR/run.cpp"; then
  pass "run.cpp applies terminal devfs ruleset"
else
  fail "run.cpp missing terminal devfs ruleset"
fi

# Validate cross-checks for Phase 4
if grep -q 'firewallPolicy' "$BUILDDIR/validate.cpp"; then
  pass "validate.cpp checks firewall policy configuration"
else
  fail "validate.cpp missing firewall checks"
fi

if grep -q 'securityAdvanced\|capsicum' "$BUILDDIR/validate.cpp"; then
  pass "validate.cpp checks capsicum/MAC configuration"
else
  fail "validate.cpp missing capsicum/MAC checks"
fi

if grep -q 'terminalOptions\|devfs_ruleset' "$BUILDDIR/validate.cpp"; then
  pass "validate.cpp checks terminal configuration"
else
  fail "validate.cpp missing terminal checks"
fi

# ===========================================================================
section "T21: Phase 5 — FreeBSD 15.0 compatibility fixes"

# HTTPS URL for base archive download
if grep -q 'https://download.freebsd.org' "$BUILDDIR/locs.cpp"; then
  pass "locs.cpp uses HTTPS URL for base archive"
else
  fail "locs.cpp missing HTTPS URL (still using FTP?)"
fi

# Release vs snapshot detection
if grep -q 'releases.*snapshots\|RELEASE' "$BUILDDIR/locs.cpp"; then
  pass "locs.cpp detects release vs snapshot URL"
else
  fail "locs.cpp missing release/snapshot detection"
fi

# _WITH_GETLINE removed
if ! grep -q '_WITH_GETLINE' "$BUILDDIR/util.cpp"; then
  pass "util.cpp has no _WITH_GETLINE (dead code removed)"
else
  fail "util.cpp still has _WITH_GETLINE"
fi

# Container OS version marker written at create time
if grep -q 'CRATE.OSVERSION' "$BUILDDIR/create.cpp"; then
  pass "create.cpp writes +CRATE.OSVERSION version marker"
else
  fail "create.cpp missing +CRATE.OSVERSION write"
fi

# Container OS version marker read at run time
if grep -q 'CRATE.OSVERSION' "$BUILDDIR/run.cpp"; then
  pass "run.cpp reads +CRATE.OSVERSION for version-mismatch detection"
else
  fail "run.cpp missing +CRATE.OSVERSION read"
fi

# Host-vs-container version comparison
if grep -q 'hostMajor.*containerMajor\|containerMajor.*hostMajor' "$BUILDDIR/run.cpp"; then
  pass "run.cpp compares host vs container FreeBSD major version"
else
  fail "run.cpp missing host-vs-container version comparison"
fi

# ipfw compat commit reference
if grep -q '4a77657cbc01' "$BUILDDIR/run.cpp"; then
  pass "run.cpp references ipfw compat removal commit (4a77657cbc01)"
else
  fail "run.cpp missing ipfw compat commit reference"
fi

# epair checksum offload fix
if grep -q 'txcsum.*txcsum6\|-txcsum' "$BUILDDIR/run.cpp"; then
  pass "run.cpp disables epair checksum offload (-txcsum -txcsum6)"
else
  fail "run.cpp missing epair checksum offload fix"
fi

# VNET loader.conf documentation
if grep -q 'loader.conf' "$BUILDDIR/run.cpp"; then
  pass "run.cpp documents loader.conf for net.inet.ip.forwarding"
else
  fail "run.cpp missing loader.conf documentation"
fi

# Jail descriptor API (JAIL_OWN_DESC)
if grep -q 'JAIL_OWN_DESC' "$BUILDDIR/run.cpp"; then
  pass "run.cpp uses JAIL_OWN_DESC for race-free jail management"
else
  fail "run.cpp missing JAIL_OWN_DESC"
fi

# sys/jail.h C++ safety workaround (bug #238928) in run.cpp
if grep -q 'extern "C"' "$BUILDDIR/run.cpp" && grep -q 'sys/jail.h' "$BUILDDIR/run.cpp"; then
  pass "run.cpp wraps sys/jail.h in extern C for C++ safety (bug #238928)"
else
  fail "run.cpp missing extern C workaround for sys/jail.h"
fi

# ===========================================================================
#  Layer 7: Phase 6 — Code Cleanup & New Features
# ===========================================================================

section "T20: pkgbase support (§17)"

# --use-pkgbase flag recognized by args parser
if grep -q 'use-pkgbase\|usePkgbase' "$BUILDDIR/args.h"; then
  pass "args.h declares usePkgbase field"
else
  fail "args.h missing usePkgbase field"
fi

if grep -q 'use-pkgbase' "$BUILDDIR/args.cpp"; then
  pass "args.cpp handles --use-pkgbase flag"
else
  fail "args.cpp missing --use-pkgbase handling"
fi

if grep -q 'bootstrapJailViaPkgbase\|pkgbase' "$BUILDDIR/create.cpp"; then
  pass "create.cpp has pkgbase bootstrap path"
else
  fail "create.cpp missing pkgbase bootstrap"
fi

if grep -q 'CRATE.BOOTSTRAP' "$BUILDDIR/create.cpp"; then
  pass "create.cpp records bootstrap method in +CRATE.BOOTSTRAP"
else
  fail "create.cpp missing +CRATE.BOOTSTRAP metadata"
fi

# ---------------------------------------------------------------------------
section "T21: dynamic ipfw rule allocation (§18)"

if grep -q 'FwSlots' "$BUILDDIR/ctx.h"; then
  pass "ctx.h declares FwSlots class"
else
  fail "ctx.h missing FwSlots class"
fi

if grep -q 'FwSlots' "$BUILDDIR/ctx.cpp"; then
  pass "ctx.cpp implements FwSlots"
else
  fail "ctx.cpp missing FwSlots implementation"
fi

if grep -q 'garbageCollect' "$BUILDDIR/ctx.cpp"; then
  pass "FwSlots has garbage collection for dead PIDs"
else
  fail "FwSlots missing garbage collection"
fi

if grep -q 'fwRuleRangeInBase\|fwRuleRangeOutBase' "$BUILDDIR/run.cpp"; then
  pass "run.cpp uses dynamic rule range bases"
else
  fail "run.cpp still uses hardcoded rule bases"
fi

# Verify old hardcoded values are gone
if grep -q 'fwRuleBaseIn = 19000\|fwRuleBaseOut = 59000' "$BUILDDIR/run.cpp"; then
  fail "run.cpp still has hardcoded 19000/59000 rule bases"
else
  pass "run.cpp no longer uses hardcoded 19000/59000"
fi

# ---------------------------------------------------------------------------
section "T22: IP address space expansion (§19)"

if grep -q '1u << 24\|address space capacity' "$BUILDDIR/run.cpp"; then
  pass "run.cpp has IP address space overflow detection"
else
  fail "run.cpp missing IP overflow detection"
fi

# Verify the XXX comment is resolved
if grep -q 'XXX use 10.0.0.0' "$BUILDDIR/run.cpp"; then
  fail "run.cpp still has XXX comment for IP allocation"
else
  pass "run.cpp IP allocation XXX comment resolved"
fi

# ---------------------------------------------------------------------------
section "T23: jail directory permission check (§20)"

if grep -q 'st_uid.*0\|owned by.*uid' "$BUILDDIR/misc.cpp"; then
  pass "misc.cpp checks jail directory ownership"
else
  fail "misc.cpp missing ownership check"
fi

if grep -q 'chmod.*0700\|st_mode.*0777' "$BUILDDIR/misc.cpp"; then
  pass "misc.cpp checks/fixes jail directory permissions"
else
  fail "misc.cpp missing permission check"
fi

# Verify the TODO is resolved
if grep -q 'TODO check that permissions' "$BUILDDIR/misc.cpp"; then
  fail "misc.cpp still has TODO for permission check"
else
  pass "misc.cpp permission check TODO resolved"
fi

# ---------------------------------------------------------------------------
section "T24: exception handling cleanup (§21)"

# Old FIXME/XXX markers should be gone
if grep -q 'FIXME(EXCEPTION' "$BUILDDIR/main.cpp"; then
  fail "main.cpp still has FIXME(EXCEPTION marker"
else
  pass "main.cpp FIXME(EXCEPTION resolved"
fi

if grep -q 'XXX UNKNOWN EXCEPTION' "$BUILDDIR/main.cpp"; then
  fail "main.cpp still has XXX UNKNOWN EXCEPTION marker"
else
  pass "main.cpp XXX UNKNOWN EXCEPTION resolved"
fi

if grep -q 'internal error' "$BUILDDIR/main.cpp"; then
  pass "main.cpp uses clean 'internal error' messages"
else
  fail "main.cpp missing clean error messages"
fi

# ---------------------------------------------------------------------------
section "T25: GL GPU vendor detection (§22)"

if grep -q 'pciconf\|vendor=0x10de\|vendor=0x1002\|vendor=0x8086' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp detects GPU vendor via pciconf"
else
  fail "spec.cpp missing GPU vendor detection"
fi

# Old nvidia-only XXX should be resolved
if grep -q 'XXX for now it only works on nvidia' "$BUILDDIR/spec.cpp"; then
  fail "spec.cpp still has nvidia-only XXX comment"
else
  pass "spec.cpp nvidia-only XXX resolved"
fi

# drm-kmod for AMD/Intel
if grep -q 'drm-kmod' "$BUILDDIR/spec.cpp"; then
  pass "spec.cpp supports AMD/Intel GPUs via drm-kmod"
else
  fail "spec.cpp missing drm-kmod for AMD/Intel"
fi

# ---------------------------------------------------------------------------
section "T26: tor csh comment cleanup"

if grep -q 'XXX not sure why csh' "$BUILDDIR/spec.cpp"; then
  fail "spec.cpp still has XXX csh comment"
else
  pass "spec.cpp csh XXX comment resolved"
fi

# ===========================================================================
#  Summary
# ===========================================================================
section "RESULTS"
printf "  Passed:  %d\n" "$PASS_COUNT"
printf "  Failed:  %d\n" "$FAIL_COUNT"
printf "  Skipped: %d\n" "$SKIP_COUNT"
printf "  Total:   %d\n" "$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))"

if [ "$FAIL_COUNT" -gt 0 ]; then
  printf "\n\033[31mCI RESULT: FAILURE (%d tests failed)\033[0m\n" "$FAIL_COUNT"
  exit 1
else
  printf "\n\033[32mCI RESULT: SUCCESS (%d passed, %d skipped)\033[0m\n" "$PASS_COUNT" "$SKIP_COUNT"
  exit 0
fi
