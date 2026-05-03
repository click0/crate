// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "wireguard_runtime_pure.h"

#include <sstream>

namespace WireguardRuntimePure {

std::string validateConfigPath(const std::string &p) {
  if (p.empty())
    return "wireguard.config path is empty";
  if (p.size() > 255)
    return "wireguard.config path is longer than 255 chars";
  if (p.front() != '/')
    return "wireguard.config path must be absolute";
  // Reject `..` segments — only between slashes or at start/end.
  // We deliberately accept names containing `..` *inside* a longer
  // segment (e.g. `foo..bar.conf`) since FreeBSD allows them.
  size_t i = 0;
  while (i < p.size()) {
    auto slash = p.find('/', i);
    auto end = slash == std::string::npos ? p.size() : slash;
    auto seg = p.substr(i, end - i);
    if (seg == "..")
      return "wireguard.config path must not contain '..' segments";
    i = end + 1;
    if (slash == std::string::npos) break;
  }
  for (char c : p) {
    if (c == ';' || c == '`' || c == '$' || c == '|' || c == '&'
        || c == '<' || c == '>' || c == '\\' || c == '\n' || c == '\r') {
      std::ostringstream os;
      os << "wireguard.config path contains shell metacharacter '";
      if (c == '\n')      os << "\\n";
      else if (c == '\r') os << "\\r";
      else                os << c;
      os << "'";
      return os.str();
    }
  }
  return "";
}

std::vector<std::string> buildUpArgv(const std::string &configPath) {
  return {"/usr/local/bin/wg-quick", "up", configPath};
}

std::vector<std::string> buildDownArgv(const std::string &configPath) {
  return {"/usr/local/bin/wg-quick", "down", configPath};
}

bool isEnabled(const std::string &configPath) {
  return !configPath.empty();
}

} // namespace WireguardRuntimePure
