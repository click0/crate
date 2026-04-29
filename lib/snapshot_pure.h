// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure renderer for `crate snapshot list` output.

#pragma once

#include <iosfwd>
#include <string>
#include <vector>

namespace SnapshotPure {

// Mirror of ZfsOps::SnapshotInfo for tests. Production passes the
// real type by-converted-vector (see lib/snapshot.cpp).
struct Entry {
  std::string name;
  std::string used;
  std::string refer;
  std::string creation;
};

void renderTable(std::ostream &out, const std::string &dataset,
                 const std::vector<Entry> &snaps);
std::string renderTableStr(const std::string &dataset,
                           const std::vector<Entry> &snaps);

}
