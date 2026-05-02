// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "bridge_pure.h"

#include <sstream>

namespace BridgePure {

Action chooseAction(const Inputs &in) {
  if (in.exists) return Action::NoOp;
  return in.autoCreate ? Action::Create : Action::Error;
}

const char *actionName(Action a) {
  switch (a) {
    case Action::NoOp:   return "noop";
    case Action::Create: return "create";
    case Action::Error:  return "error";
  }
  return "unknown";
}

std::string validateBridgeName(const std::string &name) {
  if (name.empty()) return "bridge interface name is empty";
  // IFNAMSIZ on FreeBSD is 16 (including trailing NUL).
  if (name.size() > 15) return "bridge interface name is longer than 15 chars";
  bool sawAlpha = false;
  bool sawDigit = false;
  for (auto c : name) {
    bool ok = (c >= 'a' && c <= 'z')
           || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9')
           || c == '_';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in bridge name";
      return os.str();
    }
    if (c >= '0' && c <= '9') sawDigit = true;
    else                      sawAlpha = true;
  }
  if (!sawAlpha) return "bridge name must contain a driver prefix";
  if (!sawDigit) return "bridge name must end with a unit number";
  return "";
}

} // namespace BridgePure
