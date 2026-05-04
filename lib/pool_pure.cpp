// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "pool_pure.h"

#include <sstream>

namespace PoolPure {

std::string inferPool(const std::string &jailName, char separator) {
  if (jailName.empty()) return "";
  auto pos = jailName.find(separator);
  if (pos == std::string::npos) return "";
  if (pos == 0) return "";          // leading separator → no pool
  return jailName.substr(0, pos);
}

std::string validatePoolName(const std::string &name) {
  if (name.empty()) return "pool name is empty";
  if (name.size() > 32) return "pool name longer than 32 chars";
  // The wildcard token is its own beast.
  if (name == "*") return "";
  auto isAlnum = [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9');
  };
  if (!isAlnum(name.front()))
    return "pool name must start with a letter or digit";
  for (char c : name) {
    bool ok = isAlnum(c) || c == '_' || c == '-';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in pool name";
      return os.str();
    }
  }
  return "";
}

bool tokenAllowsContainer(const std::vector<std::string> &tokenPools,
                          const std::string &containerPool) {
  // No `pools:` in the token = unrestricted (pre-0.7.4 behaviour).
  if (tokenPools.empty()) return true;
  // Explicit "*" grant = unrestricted (preferred over leaving the
  // field out when the operator wants the intent to be visible
  // in the config audit).
  for (auto &p : tokenPools)
    if (p == "*") return true;
  // No-pool containers are reachable ONLY by unrestricted tokens.
  // This is intentional: once an operator opts into pool ACLs,
  // jails that don't follow the naming convention should be
  // explicitly granted (via "*") rather than silently leaked.
  if (containerPool.empty()) return false;
  for (auto &p : tokenPools)
    if (p == containerPool) return true;
  return false;
}

} // namespace PoolPure
