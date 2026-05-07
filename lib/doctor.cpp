// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// Runtime for `crate doctor` (0.7.13). Surveys the system and crate
// state, feeds results to DoctorPure for rendering. Intended to be
// the first command an operator runs when something looks off.
//
// Read-only: no syscalls modify state. Audit module skips it.
//

#include "args.h"
#include "doctor_pure.h"
#include "auto_fw_pure.h"
#include "capsicum_ops.h"
#include "commands.h"
#include "config.h"
#include "drm_session.h"
#include "ifconfig_ops.h"
#include "ipfw_ops.h"
#include "jail_query.h"
#include "net_detect.h"
#include "nv_protocol.h"
#include "pfctl_ops.h"
#include "util.h"
#include "zfs_ops.h"
#include "err.h"

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <set>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define ERR(msg...) ERR2("doctor", msg)

namespace {

// Convenience aliases.
using DoctorPure::Check;
using DoctorPure::Report;
using DoctorPure::failCheck;
using DoctorPure::passCheck;
using DoctorPure::warnCheck;

// --- check: kernel modules via kldstat -n <name> ---
//
// On FreeBSD, `kldstat -n <name>` exits 0 if the module is loaded,
// non-zero otherwise. We rely on exit status, not output, because
// kldstat formatting changes between FreeBSD releases.
//
// Modules treated as REQUIRED (FAIL if missing) vs RECOMMENDED
// (WARN if missing) — the latter only fail when a feature actually
// needs them, but doctor is a fast preflight so we surface them
// proactively.
struct ModuleSpec {
  const char *name;
  bool        required;   // true => FAIL, false => WARN
  const char *purpose;
};

const ModuleSpec kModules[] = {
  // Core jail networking — required for any vnet jail.
  {"if_bridge", true,  "vnet jails (bridge interfaces)"},
  {"if_epair",  true,  "vnet jails (paired veth-style links)"},
  // RCTL is loaded via kernel option on most installs but check anyway.
  {"racct",     false, "RCTL accounting"},
  // dummynet for network throttling (0.7.7).
  {"dummynet",  false, "crate throttle (token-bucket network limits)"},
  // ipfw if dummynet is wanted; pf is the alternative.
  {"ipfw",      false, "ipfw firewall (or use pf instead)"},
  // bhyve track (TODO2) — purely informational on systems without it.
  {"vmm",       false, "bhyve micro-VMs (TODO2)"},
  {"nmdm",      false, "bhyve console pairs (TODO2)"},
};

void checkKernelModules(Report &r) {
  for (const auto &m : kModules) {
    int st = -1;
    try {
      // execCommandGetStatus throws if exec fails entirely; non-zero
      // exit just returns the raw wait status, which we test below.
      st = Util::execCommandGetStatus(
        {"/sbin/kldstat", "-n", m.name},
        "kldstat -n");
    } catch (...) {
      // kldstat itself missing? FAIL the whole module test.
      r.checks.push_back(failCheck("kernel", m.name,
        "kldstat(8) not runnable — is this FreeBSD?"));
      continue;
    }
    bool loaded = (st == 0);
    if (loaded) {
      r.checks.push_back(passCheck("kernel", m.name,
        std::string("loaded — ") + m.purpose));
    } else if (m.required) {
      r.checks.push_back(failCheck("kernel", m.name,
        std::string("missing — ") + m.purpose +
        " — load with: kldload " + m.name));
    } else {
      r.checks.push_back(warnCheck("kernel", m.name,
        std::string("not loaded — ") + m.purpose +
        " (kldload " + m.name + " if you need it)"));
    }
  }
}

// --- check: required commands in PATH ---
//
// We don't trust $PATH in setuid context, so we hardcode the absolute
// paths used by the rest of crate (matching pathnames.h conventions).
struct CommandSpec {
  const char *path;
  bool        required;
  const char *purpose;
};

const CommandSpec kCommands[] = {
  {"/sbin/zfs",       true,  "ZFS dataset / snapshot operations"},
  {"/sbin/jail",      true,  "jail(8) lifecycle"},
  {"/usr/sbin/jexec", true,  "exec inside jails"},
  {"/usr/bin/jls",    true,  "list jails"},
  {"/sbin/ifconfig",  true,  "network interface management"},
  {"/usr/bin/grep",   true,  "used in many shell-outs"},
  {"/usr/bin/tar",    true,  "create / run extract .crate archives"},
  {"/usr/bin/xz",     true,  "compress / decompress .crate"},
  {"/sbin/rctl",      false, "RCTL limits + crate retune / throttle stats"},
  {"/sbin/ipfw",      false, "crate throttle / per-jail firewall"},
  {"/sbin/pfctl",     false, "alternative firewall via pf"},
  {"/sbin/kldstat",   false, "kernel module checks (this command itself)"},
};

void checkCommands(Report &r) {
  for (const auto &c : kCommands) {
    if (::access(c.path, X_OK) == 0) {
      r.checks.push_back(passCheck("command", c.path,
        std::string("found — ") + c.purpose));
    } else if (c.required) {
      r.checks.push_back(failCheck("command", c.path,
        std::string("not executable — ") + c.purpose));
    } else {
      r.checks.push_back(warnCheck("command", c.path,
        std::string("not found — ") + c.purpose));
    }
  }
}

// --- check: filesystem directories writable + free space ---

void checkOneDirectory(Report &r, const std::string &path,
                       std::size_t freeWarnMB,
                       const std::string &purpose) {
  struct stat st{};
  if (::stat(path.c_str(), &st) != 0) {
    r.checks.push_back(failCheck("filesystem", path,
      std::string("does not exist — ") + purpose));
    return;
  }
  if (!S_ISDIR(st.st_mode)) {
    r.checks.push_back(failCheck("filesystem", path,
      "exists but is not a directory"));
    return;
  }
  // Writable test: root always passes mode bits, so check effective
  // access via access(2) honouring the real-uid path. crate runs
  // setuid root in CLI mode and as root in daemon, so this should
  // pass. If it doesn't, the dir probably has noexec/nosuid mount
  // flags.
  if (::access(path.c_str(), W_OK) != 0) {
    r.checks.push_back(failCheck("filesystem", path,
      "exists but not writable by crated"));
    return;
  }
  // Free space.
  struct statvfs vfs{};
  if (::statvfs(path.c_str(), &vfs) == 0) {
    auto freeMB = (std::size_t)((vfs.f_bavail * (std::size_t)vfs.f_frsize)
                                / (1024UL * 1024UL));
    std::ostringstream detail;
    detail << purpose << " — " << freeMB << " MB free";
    if (freeMB < freeWarnMB) {
      detail << " (below recommended " << freeWarnMB << " MB)";
      r.checks.push_back(warnCheck("filesystem", path, detail.str()));
    } else {
      r.checks.push_back(passCheck("filesystem", path, detail.str()));
    }
  } else {
    r.checks.push_back(passCheck("filesystem", path, purpose));
  }
}

void checkDirectories(Report &r) {
  checkOneDirectory(r, "/var/run/crate", 100,
    "crated runtime state (sockets, pid)");
  checkOneDirectory(r, "/var/log/crate",  50,
    "audit log + per-jail create logs");
}

// --- check: ZFS pool health via `zpool status -x` ---
//
// zpool status -x prints "all pools are healthy" if everything is fine.
// Anything else (degraded, faulted, removed, ...) gets surfaced.

void checkZfsPools(Report &r) {
  if (::access("/sbin/zpool", X_OK) != 0) {
    r.checks.push_back(warnCheck("zfs", "zpool",
      "/sbin/zpool not executable — skipping pool health check"));
    return;
  }
  std::string out;
  try {
    out = Util::execCommandGetOutput({"/sbin/zpool", "status", "-x"},
                                      "zpool status -x");
  } catch (const std::exception &e) {
    r.checks.push_back(warnCheck("zfs", "zpool",
      std::string("zpool status -x failed: ") + e.what()));
    return;
  }
  if (out.find("all pools are healthy") != std::string::npos) {
    r.checks.push_back(passCheck("zfs", "zpool", "all pools healthy"));
  } else if (out.find("no pools available") != std::string::npos) {
    r.checks.push_back(warnCheck("zfs", "zpool",
      "no ZFS pools imported — most crate features need ZFS"));
  } else {
    // Surface the first non-empty output line as the detail so the
    // operator sees the problem at a glance.
    std::string firstLine;
    std::istringstream is(out);
    std::getline(is, firstLine);
    if (firstLine.empty()) firstLine = "see `zpool status` for details";
    r.checks.push_back(failCheck("zfs", "zpool", firstLine));
  }
}

// --- check: crated.conf parses (best effort) ---
//
// We don't try to load the full Config struct — that pulls yaml-cpp
// and we want this command to still work if the daemon's config is
// broken. Instead we just check the file exists and is readable.

void checkCratedConf(Report &r) {
  const char *path = "/usr/local/etc/crated.conf";
  if (::access(path, F_OK) != 0) {
    r.checks.push_back(passCheck("config", path,
      "absent — daemon will use built-in defaults"));
    return;
  }
  if (::access(path, R_OK) != 0) {
    r.checks.push_back(failCheck("config", path,
      "present but not readable by crated"));
    return;
  }
  // Quick syntax sniff: open + read first 4KB, look for binary garbage.
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    r.checks.push_back(failCheck("config", path, "open failed"));
    return;
  }
  std::string buf(4096, '\0');
  f.read(&buf[0], (std::streamsize)buf.size());
  buf.resize((std::size_t)f.gcount());
  for (unsigned char c : buf) {
    if (c == 0) {
      r.checks.push_back(failCheck("config", path,
        "contains NUL bytes — likely corrupt"));
      return;
    }
  }
  r.checks.push_back(passCheck("config", path, "readable, looks textual"));
}

// --- check: running jails responsive ---
//
// JailQuery::getAllJails should return a non-throwing vector. If
// libjail itself is broken (rare) it'll throw; we surface that as
// a fail. Empty list is normal (operator hasn't started anything).

void checkJails(Report &r) {
  std::vector<JailQuery::JailInfo> jails;
  try {
    jails = JailQuery::getAllJails(/*crateOnly=*/true);
  } catch (const std::exception &e) {
    r.checks.push_back(failCheck("jails", "JailQuery",
      std::string("getAllJails failed: ") + e.what()));
    return;
  }
  if (jails.empty()) {
    r.checks.push_back(passCheck("jails", "(none running)",
      "no crate-managed jails currently running"));
    return;
  }
  for (const auto &j : jails) {
    if (j.dying) {
      r.checks.push_back(warnCheck("jails", j.name,
        "marked dying — `crate clean` may help"));
    } else {
      std::ostringstream detail;
      detail << "jid=" << j.jid;
      if (!j.ip4.empty()) detail << ", ip4=" << j.ip4;
      r.checks.push_back(passCheck("jails", j.name, detail.str()));
    }
  }
}

// --- check: audit log size (warn at 50MB) ---

void checkAuditLog(Report &r) {
  const char *path = "/var/log/crate/audit.log";
  struct stat st{};
  if (::stat(path, &st) != 0) {
    r.checks.push_back(passCheck("audit", path,
      "absent — no audit events recorded yet"));
    return;
  }
  std::size_t mb = (std::size_t)st.st_size / (1024UL * 1024UL);
  std::ostringstream detail;
  detail << "size = " << mb << " MB";
  if (mb >= 100) {
    detail << " — consider rotation (newsyslog or logrotate)";
    r.checks.push_back(warnCheck("audit", path, detail.str()));
  } else {
    r.checks.push_back(passCheck("audit", path, detail.str()));
  }
}

// --- check: ipfw rule-number conflicts (0.8.14) ---
//
// crate's auto-features each reserve a high rule-number range:
//   throttle (0.7.7):       pipe 10000+jid*2,    rule 20000+jid*2
//   auto-fw   (0.8.2/0.8.3): nat  30000+jid,     rule 40000+jid
// Operator's manual ipfw rules SHOULD live at low numbers (<10000)
// to avoid colliding. Doctor scans `ipfw list` for entries in the
// reserved ranges that didn't come from crate (no matching jail) —
// that's a sign of an operator typo or a stale rule from a
// destroyed jail.

void checkIpfwReservedRanges(Report &r) {
  if (::access("/sbin/ipfw", X_OK) != 0) {
    r.checks.push_back(passCheck("network", "ipfw",
      "/sbin/ipfw not present — skipping reserved-range check"));
    return;
  }
  std::string out;
  try {
    out = Util::execCommandGetOutput({"/sbin/ipfw", "-q", "list"},
                                      "ipfw -q list");
  } catch (const std::exception &e) {
    r.checks.push_back(warnCheck("network", "ipfw",
      std::string("ipfw list failed: ") + e.what()));
    return;
  }
  // Look at first column (rule number) of each line. Flag rules
  // in the reserved ranges that don't correspond to a running jail.
  std::vector<JailQuery::JailInfo> jails;
  try {
    jails = JailQuery::getAllJails(/*crateOnly=*/true);
  } catch (...) {}

  std::set<unsigned> validNatRuleIds;
  std::set<unsigned> validThrottleRuleIds;
  for (const auto &j : jails) {
    validNatRuleIds.insert(40000u + (unsigned)j.jid);  // auto-fw
    validThrottleRuleIds.insert(20000u + (unsigned)j.jid * 2u);
    validThrottleRuleIds.insert(20000u + (unsigned)j.jid * 2u + 1u);
  }

  std::istringstream is(out);
  std::string line;
  unsigned orphanCount = 0;
  while (std::getline(is, line)) {
    // First whitespace-separated token is the rule number.
    std::size_t sp = line.find(' ');
    if (sp == std::string::npos) continue;
    auto ruleNumStr = line.substr(0, sp);
    unsigned n = 0;
    bool digits = !ruleNumStr.empty();
    for (char c : ruleNumStr) {
      if (c < '0' || c > '9') { digits = false; break; }
      n = n * 10 + (unsigned)(c - '0');
    }
    if (!digits) continue;
    if (n >= 20000 && n < 30000) {
      // throttle range
      if (!validThrottleRuleIds.count(n)) orphanCount++;
    } else if (n >= 40000 && n < 50000) {
      // auto-fw NAT-rule range
      if (!validNatRuleIds.count(n)) orphanCount++;
    }
  }
  if (orphanCount == 0) {
    r.checks.push_back(passCheck("network", "ipfw",
      "no orphan rules in crate-reserved ranges (20000+, 40000+)"));
  } else {
    std::ostringstream detail;
    detail << orphanCount << " ipfw rule(s) in crate-reserved ranges "
              "without a matching running jail — likely stale from "
              "a destroyed jail; clean with `ipfw delete <N>` or wait "
              "for next `crate clean` to surface them";
    r.checks.push_back(warnCheck("network", "ipfw", detail.str()));
  }
}

// --- check: per-jail RCTL drift (0.8.14) ---
//
// When a spec declares `limits: { memoryuse: 2G }`, crate run
// loads an rctl rule. Operators sometimes hand-edit rules later
// via `rctl -a/-r`, leaving the kernel state out of sync with
// what `crate inspect` would report from the spec.
//
// Doctor surfaces "rules present" / "rules absent" — we can't
// know the spec at doctor time without re-loading, so this is
// information rather than an authoritative drift check.

void checkRctlPresence(Report &r) {
  if (::access("/sbin/rctl", X_OK) != 0) {
    r.checks.push_back(passCheck("network", "rctl",
      "/sbin/rctl not present — skipping RCTL presence check"));
    return;
  }
  std::vector<JailQuery::JailInfo> jails;
  try {
    jails = JailQuery::getAllJails(/*crateOnly=*/true);
  } catch (...) { return; }
  for (const auto &j : jails) {
    std::string out;
    try {
      out = Util::execCommandGetOutput(
        {"/sbin/rctl", "-l", "jail:" + j.name},
        "rctl -l jail");
    } catch (...) {
      r.checks.push_back(warnCheck("network", j.name,
        "rctl -l failed — cannot verify RCTL rules"));
      continue;
    }
    // Count non-empty lines as "rules present".
    unsigned ruleCount = 0;
    std::istringstream is(out);
    std::string line;
    while (std::getline(is, line)) if (!line.empty()) ruleCount++;
    if (ruleCount > 0) {
      r.checks.push_back(passCheck("network", j.name,
        "rctl rules: " + std::to_string(ruleCount)
        + " (verify with `crate inspect " + j.name + "`)"));
    } else {
      r.checks.push_back(warnCheck("network", j.name,
        "no rctl rules — jail can OOM the host (FAIL if "
        "spec declared limits:; check `crate inspect`)"));
    }
  }
}

// --- check: auto-fw rules loaded for each running jail (0.8.9) ---
//
// 0.8.0+ auto-loads SNAT/rdr rules into per-jail anchors (pf) or
// nat instances (ipfw). If those rules go missing — pf flushed by
// operator, ipfw rules deleted — outbound traffic from the jail
// silently breaks. doctor now surfaces the mismatch.
//
// For pf: invoke `pfctl -a crate/<jailXname> -s nat` and check
// for at least one rule. If the anchor is empty when the jail's
// spec uses mode:auto + bridge, that's a FAIL.
//
// For ipfw: invoke `ipfw nat <natId> show` and check exit code.
//
// Caveat: we don't know the jail's spec at doctor time without
// re-loading the .crate file. As a proxy, we check for ANY pf
// anchor named crate/<jailXname>* with rules vs no anchor; the
// presence/absence is informational rather than authoritative.
// Operators who don't use mode:auto may legitimately have empty
// anchors — those get a soft WARN, not FAIL.

void checkAutoFwRules(Report &r) {
  // Fast path: if pf isn't loaded at all, skip — auto-fw via ipfw
  // path is checked separately, and if neither is loaded, the
  // existing kernel-module check has already FAIL'd.
  bool pfLoaded = false;
  try {
    pfLoaded = (Util::execCommandGetStatus(
      {"/sbin/kldstat", "-n", "pf"}, "kldstat pf") == 0);
  } catch (...) { pfLoaded = false; }

  std::vector<JailQuery::JailInfo> jails;
  try {
    jails = JailQuery::getAllJails(/*crateOnly=*/true);
  } catch (...) {
    // checkJails already FAIL'd; nothing useful to add.
    return;
  }
  if (jails.empty()) {
    r.checks.push_back(passCheck("auto-fw", "(no jails)",
      "no crate-managed jails running — nothing to check"));
    return;
  }

  for (const auto &j : jails) {
    // Synthesise the same jail-x-name run.cpp uses for the anchor.
    auto jailXname = j.name + "_pid?";  // doctor doesn't know the
                                         // run.cpp pid; query by
                                         // anchor list instead.
    if (pfLoaded) {
      // List all pf anchors and look for one starting with crate/<j.name>_pid.
      std::string out;
      try {
        out = Util::execCommandGetOutput(
          {"/sbin/pfctl", "-a", "crate", "-s", "Anchors"},
          "pfctl list anchors");
      } catch (const std::exception &ex) {
        r.checks.push_back(warnCheck("auto-fw", j.name,
          std::string("pfctl -s Anchors failed: ") + ex.what()
          + " — cannot verify auto-fw rule"));
        continue;
      }
      // pfctl -s Anchors output: one anchor per line, prefixed by
      // the parent. Look for a line containing "crate/<j.name>_pid".
      std::string needle = "crate/" + j.name + "_pid";
      bool found = false;
      std::istringstream is(out);
      std::string line;
      while (std::getline(is, line)) {
        if (line.find(needle) != std::string::npos) {
          found = true;
          break;
        }
      }
      if (found) {
        r.checks.push_back(passCheck("auto-fw", j.name,
          "pf anchor present (auto-fw active)"));
      } else {
        // Could be intentional (jail uses NAT mode without auto-fw,
        // or operator runs custom rules). Soft WARN.
        r.checks.push_back(warnCheck("auto-fw", j.name,
          "no crate/" + j.name + "_pid* pf anchor — auto-fw "
          "inactive (OK for jails not using mode:auto; FAIL for "
          "auto-mode jails — outbound traffic likely broken)"));
      }
    } else {
      // ipfw path: presence of nat instance natIdForJail(jid).
      // 0.8.2 conventions.
      unsigned natId = AutoFwPure::natIdForJail(j.jid);
      int st = -1;
      try {
        st = Util::execCommandGetStatus(
          {"/sbin/ipfw", "nat", std::to_string(natId), "show"},
          "ipfw nat show");
      } catch (...) { st = -1; }
      if (st == 0) {
        r.checks.push_back(passCheck("auto-fw", j.name,
          "ipfw NAT instance " + std::to_string(natId)
          + " present (auto-fw active)"));
      } else {
        r.checks.push_back(warnCheck("auto-fw", j.name,
          "no ipfw NAT instance " + std::to_string(natId)
          + " — auto-fw inactive (OK for jails not using mode:auto; "
          "FAIL for auto-mode jails — outbound traffic likely broken)"));
      }
    }
  }
}

// 0.8.23: DRM session via libseat. Surfaces seatd setup issues
// before they bite at jail start time. Three outcomes:
//   - libseat not compiled in -> info-level pass (operator's
//     build doesn't include the feature; not a fault)
//   - /dev/dri/card0 absent on host -> info pass (no GPU)
//   - libseat present + /dev/dri/card0 present + probe works -> pass
//   - libseat present + /dev/dri/card0 present + probe fails -> warn
//     (seatd not running, user not on seat0, etc.)
void checkDrmSession(Report &r) {
  if (!DrmSession::available()) {
    r.checks.push_back(passCheck("gui", "drm-session-libseat",
      "crate built without WITH_LIBSEAT — DRM device acquisition "
      "uses direct open(O_RDWR). Fine for the setuid-root crate "
      "today; matters once rootless containers ship."));
    return;
  }
  struct stat st{};
  if (::stat("/dev/dri/card0", &st) != 0) {
    r.checks.push_back(passCheck("gui", "drm-session-libseat",
      "no /dev/dri/card0 on host — skipping libseat probe."));
    return;
  }
  if (DrmSession::probeDevice("/dev/dri/card0")) {
    r.checks.push_back(passCheck("gui", "drm-session-libseat",
      "libseat session opens and grabs /dev/dri/card0 — rootless "
      "GPU jails will work once that path lands."));
  } else {
    r.checks.push_back(warnCheck("gui", "drm-session-libseat",
      "libseat compiled in but probeDevice('/dev/dri/card0') "
      "failed. seatd not running, or current user not on an active "
      "seat. `service seatd onestart` and re-run `crate doctor`."));
  }
}

// 0.8.24: Capsicum / casper sandbox readiness. Surfaces:
//   - whether crate was built with HAVE_CAPSICUM at all
//   - whether `audit_syslog: true` is wired (operator opt-in for
//     dual-write of audit events to syslog via cap_syslog)
// Doesn't actually open the cap_syslog channel here — that would
// leave a dangling fd. The fact that the operator set
// audit_syslog AND CapsicumOps is built in is the actionable
// signal; runtime initialisation happens lazily in audit.cpp.
// 0.8.26: native subsystem-API availability. Each of these
// namespaces has a `bool available()` predicate compiled at build
// time (true when the corresponding HAVE_* macro was defined +
// the library linked). The runtime falls back to fork+exec'ing
// the equivalent shell utility (zfs(8), ifconfig(8), pfctl(8),
// ipfw(8)) when the native path isn't available.
//
// We surface the build matrix to operators via `crate doctor` so
// they can see the perf characteristics of their build at a
// glance. No runtime change — just visibility.
//
// All four checks emit pass severity (informational); fork+exec
// is a fully-supported path, just slower per-call. Operators
// who care about latency can rebuild with the appropriate
// HAVE_LIB* macros and the runtime will pick up the native
// path on next invocation.
// 0.8.27: nvlist-protocol round-trip — verifies the
// scaffolding for the future control-plane v2 still works.
// Currently the only production caller of NvProtocol; surfacing
// it here means the code path stays exercised so it doesn't
// rot. Failure mode is informational on Linux dev builds (libnv
// unavailable) and a warning on FreeBSD (libnv broken or
// socketpair failure — exotic).
void checkNvProtocol(Report &r) {
  if (!NvProtocol::available()) {
    r.checks.push_back(passCheck("native-api", "nvlist-protocol",
      "libnv not built in (Linux dev build) — nvlist wire format "
      "for the future control-plane v2 unavailable. Fine on "
      "FreeBSD; on Linux the production crate uses HTTP+JSON "
      "anyway."));
    return;
  }
  if (NvProtocol::selfTest()) {
    r.checks.push_back(passCheck("native-api", "nvlist-protocol",
      "libnv round-trip works — scaffolding for the future "
      "control-plane v2 (replaces hand-rolled HTTP parsing in "
      "daemon/control_socket_pure.cpp) is ready."));
  } else {
    r.checks.push_back(warnCheck("native-api", "nvlist-protocol",
      "libnv built in but socketpair round-trip failed — exotic. "
      "Re-run `crate doctor` after a system update; if it persists, "
      "file a bug with the FreeBSD version."));
  }
}

void checkNativeApis(Report &r) {
  r.checks.push_back(passCheck("native-api", "libzfs",
    ZfsOps::available()
      ? "linked — snapshot/clone/jail-attach skip fork+exec'ing zfs(8)"
      : "not linked — falls back to /sbin/zfs (rebuild with HAVE_LIBZFS=1 to skip fork+exec)"));

  r.checks.push_back(passCheck("native-api", "libifconfig",
    IfconfigOps::available()
      ? "linked — interface ops skip fork+exec'ing ifconfig(8)"
      : "not linked — falls back to /sbin/ifconfig (rebuild with HAVE_LIBIFCONFIG=1)"));

  r.checks.push_back(passCheck("native-api", "libpfctl",
    PfctlOps::available()
      ? "linked — pf anchor + rule ops skip fork+exec'ing pfctl(8)"
      : "not linked — falls back to /sbin/pfctl (rebuild with HAVE_LIBPFCTL=1)"));

  r.checks.push_back(passCheck("native-api", "ipfw-native",
    IpfwOps::available()
      ? "kernel ipfw socket reachable — rule ops skip fork+exec'ing ipfw(8)"
      : "kernel ipfw not loaded or not reachable — rule ops fork+exec /sbin/ipfw"));
}

void checkCapsicumSandbox(Report &r) {
  bool capsicum = CapsicumOps::available();
  bool wantSyslog = Config::get().auditSyslog;

  if (!capsicum && wantSyslog) {
    r.checks.push_back(warnCheck("audit", "capsicum-casper",
      "audit_syslog: true but crate built without HAVE_CAPSICUM — "
      "falling back to plain syslog(3) (still works; loses "
      "cap_enter resilience)."));
    return;
  }
  if (!capsicum) {
    r.checks.push_back(passCheck("audit", "capsicum-casper",
      "crate built without HAVE_CAPSICUM — audit log writes to "
      "file only. Set HAVE_CAPSICUM at build time + audit_syslog: "
      "true in crate.yml to also ship audit events to syslog via "
      "cap_syslog."));
    return;
  }
  if (wantSyslog) {
    r.checks.push_back(passCheck("audit", "capsicum-casper",
      "casper available; audit_syslog: true — audit events are "
      "dual-written to file + syslog via cap_syslog."));
  } else {
    r.checks.push_back(passCheck("audit", "capsicum-casper",
      "casper available but audit_syslog: false (default). Set "
      "audit_syslog: true in crate.yml to ship audit events to "
      "syslog in addition to file."));
  }
}

} // anon

bool doctorCommand(const Args &args) {
  // 0.8.35: --refresh-cache drops in-memory caches before running
  // checks. NetDetect caches the default-route interface for the
  // process lifetime; under crated (long-lived daemon) operators
  // running `crate doctor --refresh-cache` after rebooting the
  // upstream router get an immediate re-detect rather than waiting
  // for crated to restart. Cheap — just clears a static string.
  if (args.doctorRefreshCache)
    NetDetect::clearCache();

  Report r;
  checkKernelModules(r);
  checkCommands(r);
  checkDirectories(r);
  checkZfsPools(r);
  checkCratedConf(r);
  checkJails(r);
  checkAuditLog(r);
  checkAutoFwRules(r);             // 0.8.9
  checkIpfwReservedRanges(r);      // 0.8.14
  checkRctlPresence(r);            // 0.8.14
  checkDrmSession(r);              // 0.8.23
  checkCapsicumSandbox(r);         // 0.8.24
  checkNativeApis(r);              // 0.8.26
  checkNvProtocol(r);              // 0.8.27

  if (args.doctorJson) {
    std::cout << DoctorPure::renderJson(r) << std::endl;
  } else {
    std::cout << DoctorPure::renderText(r, args.noColor);
  }

  // Return value: dispatch in cli/main.cpp inverts it for exit code.
  // We want to return non-zero on warn or fail so cron pipelines can
  // act on it. main.cpp does `succ ? 0 : 1` — we hijack that by
  // returning false when there's a warn-or-worse, matching the
  // exitCodeFor convention.
  int code = DoctorPure::exitCodeFor(r);
  return code == 0;
}
