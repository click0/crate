// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Runtime side of the crated Capsicum sandbox (0.7.14).
//
// Per-fd cap_rights_limit only — no whole-process cap_enter (that
// would break execve(2) of subprocess utilities like rctl/jail/
// jexec/ipfw that crated relies on). See sandbox_pure.h header
// for the design discussion.
//
// On Linux (no Capsicum) all functions are no-ops returning false,
// which lets the same code path compile + run for unit tests.
//

namespace Sandbox {

// Compile-time check: was Capsicum / Casper compiled in?
bool available();

// Limit a server-side listening socket to accept-only ops.
// Maps to CAP_ACCEPT + CAP_GETSOCKOPT + CAP_FSTAT.
// Returns true if the limitation was applied (only on FreeBSD with
// HAVE_CAPSICUM); returns false silently on other platforms.
bool applyListenerRights(int fd);

// Limit an accepted connection fd to recv/send/shutdown.
// Maps to CAP_RECV + CAP_SEND + CAP_SHUTDOWN + CAP_GETSOCKOPT + CAP_FSTAT.
bool applyConnectionRights(int fd);

// Limit a write-only append log fd. Maps to CAP_WRITE + CAP_FSYNC + CAP_FSTAT.
bool applyLogWriteRights(int fd);

// Limit a read-only config fd. Maps to CAP_READ + CAP_FSTAT.
bool applyConfigReadRights(int fd);

} // namespace Sandbox
