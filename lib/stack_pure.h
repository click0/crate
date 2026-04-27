// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers extracted from lib/stack.cpp for unit testing.

#pragma once

#include "err.h"

#include <cstdint>
#include <map>
#include <queue>
#include <string>
#include <vector>

namespace StackPure {

// CIDR parsing / IPv4 formatting
bool        parseCidr(const std::string &cidr, uint32_t &baseAddr, unsigned &prefixLen);
std::string ipToString(uint32_t ip);

// IPv6 address validation (POSIX inet_pton). Mirror of Net::isIpv6Address
// from lib/net.cpp; lives here so unit tests can call it without dragging
// in the full lib/net.cpp (which depends on getifaddrs / resolv.conf).
bool        isIpv6Address(const std::string &addr);

// /etc/hosts assembly
std::string ipFromCidr(const std::string &cidr);
std::string buildHostsEntries(const std::map<std::string, std::string> &nameToIp);

// Lightweight stack-entry view used by the tests.
struct StackEntry {
  std::string name;
  std::vector<std::string> depends;
};

// Templated topological sort — works for any T with `.name` (string)
// and `.depends` (vector<string>). Throws Exception on duplicates,
// unknown deps, or cycles.
template<typename T>
std::vector<T> topoSort(const std::vector<T> &entries) {
  std::map<std::string, size_t> nameIdx;
  for (size_t i = 0; i < entries.size(); i++) {
    if (nameIdx.count(entries[i].name))
      ERR2("stack", "duplicate container name '" << entries[i].name << "' in stack file")
    nameIdx[entries[i].name] = i;
  }

  for (auto &e : entries)
    for (auto &d : e.depends)
      if (!nameIdx.count(d))
        ERR2("stack", "container '" << e.name << "' depends on unknown container '" << d << "'")

  size_t n = entries.size();
  std::vector<int> inDeg(n, 0);
  std::vector<std::vector<size_t>> adj(n);

  for (size_t i = 0; i < n; i++) {
    for (auto &d : entries[i].depends) {
      size_t di = nameIdx[d];
      adj[di].push_back(i);
      inDeg[i]++;
    }
  }

  std::queue<size_t> q;
  for (size_t i = 0; i < n; i++)
    if (inDeg[i] == 0)
      q.push(i);

  std::vector<T> sorted;
  sorted.reserve(n);
  while (!q.empty()) {
    size_t cur = q.front();
    q.pop();
    sorted.push_back(entries[cur]);
    for (auto next : adj[cur]) {
      if (--inDeg[next] == 0)
        q.push(next);
    }
  }

  if (sorted.size() != n)
    ERR2("stack", "circular dependency detected in stack file")

  return sorted;
}

}
