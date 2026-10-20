// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure JSON/table rendering for `crate list`. The original lib/list.cpp
// discovers running jails (FreeBSD jail API) and prints to stdout; this
// module just formats a vector of entries into a string. Tests can build
// fake entries and assert exact output without spinning a jail.

#pragma once

#include <iosfwd>
#include <string>
#include <vector>

namespace ListPure {

struct Entry {
  int jid = 0;
  std::string name;
  std::string path;
  std::string ip;
  std::string hostname;
  std::string ports;
  std::string mounts;
  bool hasHealthcheck = false;
};

void renderJson(std::ostream &out, const std::vector<Entry> &entries);
void renderTable(std::ostream &out, const std::vector<Entry> &entries);

// Convenience: render to a string.
std::string renderJsonStr(const std::vector<Entry> &entries);
std::string renderTableStr(const std::vector<Entry> &entries);

// 1.1.48: control characters (< 0x20, 0x7f) replaced by '?'. The kernel
// host.hostname is spec-controllable (allow.set_hostname) and non-crate
// jails have arbitrary names; both used to reach the operator's terminal
// raw, so a jail could inject escape sequences into `crate list`.
std::string sanitizeForTerminal(const std::string &s);

}
