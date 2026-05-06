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
#include "commands.h"
#include "jail_query.h"
#include "util.h"
#include "err.h"

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

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

} // anon

bool doctorCommand(const Args &args) {
  Report r;
  checkKernelModules(r);
  checkCommands(r);
  checkDirectories(r);
  checkZfsPools(r);
  checkCratedConf(r);
  checkJails(r);
  checkAuditLog(r);

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
