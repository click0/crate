// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "sandbox.h"
#include "sandbox_pure.h"

#ifdef HAVE_CAPSICUM
#include <sys/capsicum.h>
#endif

namespace Sandbox {

bool available() {
#ifdef HAVE_CAPSICUM
  return true;
#else
  return false;
#endif
}

#ifdef HAVE_CAPSICUM

namespace {
// Apply a cap_rights_t built from variadic CAP_* macros to fd.
// Returns true on success.
template <class... Rights>
bool apply(int fd, Rights... rights) {
  cap_rights_t r;
  cap_rights_init(&r, rights...);
  return ::cap_rights_limit(fd, &r) == 0;
}
} // anon

bool applyListenerRights(int fd) {
  // Listener fd: only accept(2), socket-level introspection, fstat.
  // Counts must match SandboxPure::rightCountFor(FdRole::Listener).
  return apply(fd, CAP_ACCEPT, CAP_GETSOCKOPT, CAP_FSTAT);
}

bool applyConnectionRights(int fd) {
  // Accepted-connection fd: bidirectional bytes, shutdown, sockopt
  // queries, fstat. No accept (it's a connected socket), no
  // bind, no listen.
  return apply(fd, CAP_RECV, CAP_SEND, CAP_SHUTDOWN,
                   CAP_GETSOCKOPT, CAP_FSTAT);
}

bool applyLogWriteRights(int fd) {
  return apply(fd, CAP_WRITE, CAP_FSYNC, CAP_FSTAT);
}

bool applyConfigReadRights(int fd) {
  return apply(fd, CAP_READ, CAP_FSTAT);
}

#else  // !HAVE_CAPSICUM — no-ops on Linux + other non-Capsicum platforms

bool applyListenerRights(int)   { return false; }
bool applyConnectionRights(int) { return false; }
bool applyLogWriteRights(int)   { return false; }
bool applyConfigReadRights(int) { return false; }

#endif

} // namespace Sandbox
