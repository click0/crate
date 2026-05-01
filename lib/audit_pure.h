// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers for crate's audit log (compliance trail).
//
// Format
// ------
// One JSON object per line ("JSON Lines"), appended to
// /var/log/crate/audit.log (or wherever Config::Settings::logs points).
// Schema:
//   {
//     "ts":      "2026-05-01T20:55:01Z",        // UTC, ISO 8601
//     "pid":     12345,
//     "uid":     1000,                          // real uid (caller)
//     "euid":    0,                             // effective uid (typically 0 — setuid)
//     "gid":     1000,
//     "egid":    0,
//     "user":    "alice",                       // passwd entry for uid (best-effort)
//     "host":    "build-server",
//     "cmd":     "create",                      // create / run / stop / ...
//     "target":  "firefox.crate",               // primary subject
//     "argv":    "crate create -s spec.yml ...",// full invocation
//     "outcome": "started" | "ok" | "failed: <msg>"
//   }
//
// Why: setuid-root binary on a multi-user host needs an audit trail
// (which user did what, when). Per POSIX, getuid() returns the real
// uid of the invoking user even though euid is 0; record both so a
// reviewer sees "uid=1000 (alice) acted via euid=0".

#pragma once

#include <string>
#include <vector>

class Args;

namespace AuditPure {

struct Event {
  std::string ts;          // "2026-05-01T20:55:01Z"
  long        pid = 0;
  long        uid = 0;
  long        euid = 0;
  long        gid = 0;
  long        egid = 0;
  std::string user;        // empty if passwd lookup failed
  std::string host;
  std::string cmd;         // human label e.g. "create"
  std::string target;      // primary subject e.g. spec / archive / target name
  std::string argv;        // joined command line
  std::string outcome;     // "started" / "ok" / "failed: ..." / etc.
};

// Render an Event as one JSON line (no trailing newline).
std::string renderJson(const Event &ev);

// Pick a sensible "target" string for the audit record from the
// Args struct, depending on the command. Returns empty string for
// commands without a meaningful target (e.g. List, Clean).
std::string pickTarget(const Args &args);

// Format the current time as "YYYY-MM-DDTHH:MM:SSZ" (UTC).
std::string formatTimestampUtc(long timeT);

// Join argv into a single space-separated string, with each arg
// shell-quoted so the line can be replayed.
std::string joinArgv(int argc, char **argv);

}
