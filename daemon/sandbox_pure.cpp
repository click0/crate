// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "sandbox_pure.h"

#include <sstream>

namespace SandboxPure {

const char *labelFor(FdRole r) {
  switch (r) {
  case FdRole::Listener:    return "listener";
  case FdRole::Connection:  return "connection";
  case FdRole::LogWrite:    return "log-write";
  case FdRole::ConfigRead:  return "config-read";
  }
  return "?";
}

unsigned rightCountFor(FdRole r) {
  switch (r) {
  case FdRole::Listener:    return 3;
  case FdRole::Connection:  return 5;
  case FdRole::LogWrite:    return 3;
  case FdRole::ConfigRead:  return 2;
  }
  return 0;
}

std::string describe(int fd, FdRole r) {
  std::ostringstream o;
  o << "sandbox: limit fd " << fd << " as " << labelFor(r)
    << " (" << rightCountFor(r) << " rights)";
  return o.str();
}

} // namespace SandboxPure
