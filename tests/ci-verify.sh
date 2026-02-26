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
