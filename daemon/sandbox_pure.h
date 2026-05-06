// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for the crated Capsicum sandbox plane (0.7.14).
//
// crated already managed `lib/capsicum_ops.cpp` infrastructure
// (cap_init, casper, cap_rights_limit) but never wired it into its
// own listen/accept paths. 0.7.14 activates per-fd rights limiting
// for the sockets and audit log. Whole-process `cap_enter()` is
// NOT used: crated spawns subprocesses (rctl, jail, jexec, ipfw,
// ...) that need path-based access, and cap_enter would break
// execve(2) for those. A future hardening track can split crated
// into a sandboxed network front + privileged worker (privsep);
// see CHANGELOG note in 0.7.14.
//
// This module owns:
//   - the FdRole enum (declarative classification of fds)
//   - stable labels for diagnostics + audit
//   - a stable "expected number of rights" count, used by tests so
//     a typo in the runtime side surfaces as a count regression
//
// All cap_rights_init / cap_rights_limit calls live in
// daemon/sandbox.cpp behind `#ifdef HAVE_CAPSICUM`.
//

#include <string>

namespace SandboxPure {

enum class FdRole {
  Listener,    // server socket; accept-only
  Connection,  // accepted client socket; recv/send/shutdown
  LogWrite,    // append-only log file; write/fsync
  ConfigRead,  // config file held open; read only
};

// Stable text label for diagnostics ("listener", "connection", ...).
// Used by `crated` startup log lines and (future) `crate doctor`
// integration that wants to report which fds are sandboxed.
const char *labelFor(FdRole r);

// Expected count of cap_rights_t entries the runtime will apply for
// a given role. Stable across releases — if you bump the runtime
// to add a new right, also bump this count and update the tests.
// This keeps the runtime's rights table from silently drifting.
//
// Mapping (matches daemon/sandbox.cpp):
//   Listener    -> 3   (CAP_ACCEPT, CAP_GETSOCKOPT, CAP_FSTAT)
//   Connection  -> 5   (CAP_RECV, CAP_SEND, CAP_SHUTDOWN,
//                       CAP_GETSOCKOPT, CAP_FSTAT)
//   LogWrite    -> 3   (CAP_WRITE, CAP_FSYNC, CAP_FSTAT)
//   ConfigRead  -> 2   (CAP_READ, CAP_FSTAT)
unsigned rightCountFor(FdRole r);

// Build a one-line human-readable description of a sandbox event,
// suitable for `crated`'s startup log. Stable format:
//   "sandbox: limit fd <fd> as <label> (<count> rights)"
std::string describe(int fd, FdRole r);

} // namespace SandboxPure
