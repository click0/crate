// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure formatter for per-user audit lines (0.9.13, rootless track).
//
// 0.9.8-0.9.12 established the per-user namespacing contract.
// 0.9.13 takes the first concrete wiring step: when a privileged
// verb is invoked AND the operator's uid is known AND the daemon
// config has `rootless_per_user: true`, a JSON-Lines audit record
// is appended to `/var/run/crate/<uid>/audit.log` (path from
// runtime_paths_pure::perUserAuditLog).
//
// This module formats the audit line. The on-disk write is in
// daemon/audit_per_user.cpp. Pure separation lets the wire-format
// be locked down by tests without spinning up a real filesystem.
//
// Format: one JSON object per line, no trailing comma. Field
// order is stable so operators can grep-and-jq scripts predictably.
// Schema:
//
//   {
//     "ts": 1715250000,            // unix epoch seconds
//     "uid": 1000,                 // operator uid
//     "verb": "set_rctl",          // privops verb name
//     "status": 200,               // HTTP status from dispatcher
//     "outcome": "ok"              // "ok" if 2xx, otherwise short reason
//   }
//
// "outcome" is a short token classifying the response:
//   2xx  -> "ok"
//   400  -> "parse_or_validate"
//   403  -> "forbidden"
//   404  -> "not_found"
//   429  -> "rate_limit"
//   5xx  -> "server_error"
//   else -> "other"
//
// Detail (the response body) is intentionally NOT emitted — it
// can contain operator-supplied content (jail names, paths) that
// inflates the audit log. The system audit (cap_syslog dual-write
// in lib/audit.cpp) keeps the canonical record with full detail.
//

#include <cstdint>
#include <string>

namespace AuditPerUserPure {

struct Record {
  long     timestamp = 0;     // unix epoch seconds (operator-supplied for testability)
  uint32_t uid = 0;
  std::string verb;            // e.g. "set_rctl"
  int      status = 0;         // HTTP status from dispatcher
};

// Format a JSON-Lines record (no trailing newline — caller appends
// after combining with any other lines). Returns the JSON object
// as a std::string.
std::string formatLine(const Record &r);

// Classify a status code into a short outcome token. Exposed for
// tests; callers normally just call formatLine.
const char *outcomeFor(int status);

} // namespace AuditPerUserPure
