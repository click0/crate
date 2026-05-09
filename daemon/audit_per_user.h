// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Per-user audit-log writer (0.9.13, rootless track).
//
// Best-effort append-only writer for /var/run/crate/<uid>/audit.log.
// Used by daemon/privops_handlers.cpp's dispatcher when the
// operator's uid is known (uid > 0) AND the daemon config has
// `rootless_per_user: true`.
//
// "Best-effort" semantics:
//   - The verb call must NOT fail just because we can't open the
//     audit log. The canonical record continues to go through the
//     existing audit subsystem (lib/audit.cpp; cap_syslog dual-
//     write).
//   - mkdir of /var/run/crate/<uid> is attempted lazily on first
//     write; missing parent directory or read-only filesystem
//     turns into a logged-to-stderr warning, not an error.
//   - Concurrent writes are atomic at the line level (POSIX append
//     mode on small writes is atomic up to PIPE_BUF — we stay well
//     under that for one JSON line).
//

#include <cstdint>
#include <string>

namespace Crated {

// Append a per-user audit line for a privops verb invocation.
// Best-effort — never throws, returns true on successful write.
//
// Caller composes the line via AuditPerUserPure::formatLine.
// This function:
//   - mkdir -p /var/run/crate/<uid> (mode 0700)
//   - opens /var/run/crate/<uid>/audit.log with O_WRONLY|O_APPEND|
//     O_CREAT, mode 0600
//   - writes the line + '\n'
//   - closes
//
// On any failure logs a single line to stderr and returns false.
bool appendPerUserAuditLine(uint32_t uid, const std::string &jsonLine);

} // namespace Crated
