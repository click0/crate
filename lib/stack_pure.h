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

// 1.1.25: validators for stack-file fields that reach a root-run sink.
//
// validateStackName — container and network names. Both are YAML map
// keys that used to flow unvalidated into (a) a `printf '…' >>
// /etc/hosts` shell fragment run via `sh -c` as root and (b) the
// `dns-<network>` config-directory path that is create_directories'd,
// written, and remove_all'd as root. Constrain to [A-Za-z0-9._-],
// 1..64 chars, not "."/"..", no leading '-': that excludes quotes,
// backslashes, newlines, and '/' — so the value is inert inside the
// single-quoted printf and is a single safe path component.
std::string validateStackName(const std::string &name);

// validateStackIp — container static IPs and network gateways, which
// reach the same `sh -c` fragments. Accepts an IPv4/IPv6 literal with
// an optional /prefix; rejects any byte outside [0-9a-fA-F.:/] first,
// then requires inet_pton to accept the address part. Returns "" on
// success.
std::string validateStackIp(const std::string &ip);

// 1.1.45: does kernel jail `jailName` belong to stack container
// `container`? crate run names the jail "<name>_pid<pid>", so the test is
// an exact "<container>_pid<digits>" match — NOT a substring search,
// which made `stack exec db` pick jail "mydb_pid…".
bool jailNameMatchesContainer(const std::string &jailName, const std::string &container);

// 1.1.45: network_policy rule numbering. Rules live in 30000..39999 in
// blocks of `width`; the block is chosen from the LIVE rule list so two
// stacks (two processes) never share numbers — the old static counter
// restarted at 0 in every process, and `ipfw delete 30000` then removed
// another stack's rules.
//   ipfwRuleNumbers():   leading rule number of every `ipfw list` line
//   freePolicySlot():    first block base in [base, end] with no rule
//                        inside it; 0 when the range is full
//   policyRulesForBridge(): rule numbers in [lo, hi] whose text ends the
//                        match "via <bridge>" — what `stack down` deletes
std::vector<unsigned> ipfwRuleNumbers(const std::string &ipfwListOutput);
unsigned freePolicySlot(const std::vector<unsigned> &used,
                        unsigned base = 30000, unsigned end = 39999, unsigned width = 100);
std::vector<unsigned> policyRulesForBridge(const std::string &ipfwListOutput,
                                           const std::string &bridge,
                                           unsigned lo = 30000, unsigned hi = 39999);

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
