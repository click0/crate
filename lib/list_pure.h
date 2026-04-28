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

}
