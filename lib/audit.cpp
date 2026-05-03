// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "audit.h"
#include "audit_pure.h"
#include "args.h"
#include "config.h"
#include "util.h"
#include "err.h"

#include <fcntl.h>
#include <pwd.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <iostream>
#include <string>

namespace Audit {

// Build an Event with the current process's uid/gid/host/timestamp.
// These are cheap syscalls and do not throw — failures fall back to 0
// or empty strings rather than aborting the audit (a missing audit
// line shouldn't block a working command).
static AuditPure::Event makeEvent(int argc, char **argv, const Args &args,
                                  const std::string &outcome) {
  AuditPure::Event ev;
  ev.ts   = AuditPure::formatTimestampUtc(::time(nullptr));
  ev.pid  = static_cast<long>(::getpid());
  ev.uid  = static_cast<long>(::getuid());
  ev.euid = static_cast<long>(::geteuid());
  ev.gid  = static_cast<long>(::getgid());
  ev.egid = static_cast<long>(::getegid());

  // Resolve username (best-effort)
  if (struct passwd *pw = ::getpwuid(::getuid())) {
    if (pw->pw_name) ev.user = pw->pw_name;
  }

  // Hostname (best-effort)
  try {
    ev.host = Util::getSysctlString("kern.hostname");
  } catch (...) {
    char buf[256];
    if (::gethostname(buf, sizeof(buf)) == 0) {
      buf[sizeof(buf) - 1] = '\0';
      ev.host = buf;
    }
  }

  // Command label
  switch (args.cmd) {
  case CmdCreate:   ev.cmd = "create";   break;
  case CmdRun:      ev.cmd = "run";      break;
  case CmdValidate: ev.cmd = "validate"; break;
  case CmdSnapshot: ev.cmd = "snapshot"; break;
  case CmdExport:   ev.cmd = "export";   break;
  case CmdImport:   ev.cmd = "import";   break;
  case CmdGui:      ev.cmd = "gui";      break;
  case CmdList:     ev.cmd = "list";     break;
  case CmdInfo:     ev.cmd = "info";     break;
  case CmdClean:    ev.cmd = "clean";    break;
  case CmdConsole:  ev.cmd = "console";  break;
  case CmdStack:    ev.cmd = "stack";    break;
  case CmdStats:    ev.cmd = "stats";    break;
  case CmdLogs:     ev.cmd = "logs";     break;
  case CmdStop:     ev.cmd = "stop";     break;
  case CmdRestart:  ev.cmd = "restart";  break;
  case CmdTop:      ev.cmd = "top";      break;
  case CmdInterDns: ev.cmd = "inter-dns"; break;
  case CmdVpn:      ev.cmd = "vpn";       break;
  case CmdInspect:  ev.cmd = "inspect";   break;
  case CmdMigrate:  ev.cmd = "migrate";   break;
  default:          ev.cmd = "?";
  }

  ev.target  = AuditPure::pickTarget(args);
  ev.argv    = AuditPure::joinArgv(argc, argv);
  ev.outcome = outcome;
  return ev;
}

// Read-only commands don't need to be audited — they don't change
// state. Skip them to keep the log clean and inexpensive on busy
// query workloads (e.g. `crate list -j` polled by a hub).
static bool isReadOnly(Command c) {
  switch (c) {
  case CmdValidate:
  case CmdList:
  case CmdInfo:
  case CmdStats:
  case CmdLogs:
  case CmdTop:
  case CmdInspect:
    return true;
  default:
    return false;
  }
}

static void writeRecord(const AuditPure::Event &ev) {
  auto &cfg = Config::get();
  if (cfg.logs.empty())
    return;
  auto path = cfg.logs + "/audit.log";

  // Best-effort: ensure logs dir exists. Failure here -> drop the
  // audit line silently (don't crash the user-facing command).
  try { Util::Fs::mkdirIfNotExists(cfg.logs, 0750); } catch (...) {}

  int fd = ::open(path.c_str(),
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                  0640);
  if (fd < 0)
    return;

  auto line = AuditPure::renderJson(ev) + "\n";
  // Single write() is atomic per POSIX for size <= PIPE_BUF (4096).
  // A single audit JSON line stays well under that.
  (void)::write(fd, line.data(), line.size());
  ::close(fd);
}

void logStart(int argc, char **argv, const Args &args) {
  if (isReadOnly(args.cmd))
    return;
  writeRecord(makeEvent(argc, argv, args, "started"));
}

void logEnd(int argc, char **argv, const Args &args, const std::string &errMsg) {
  if (isReadOnly(args.cmd))
    return;
  std::string outcome = errMsg.empty() ? "ok" : ("failed: " + errMsg);
  writeRecord(makeEvent(argc, argv, args, outcome));
}

}
