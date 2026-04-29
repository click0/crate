// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "snapshot_pure.h"

#include <algorithm>
#include <ostream>
#include <sstream>

namespace SnapshotPure {

void renderTable(std::ostream &out, const std::string &dataset,
                 const std::vector<Entry> &snaps) {
  if (snaps.empty()) {
    out << "No snapshots found for " << dataset << "\n";
    return;
  }

  out << "NAME" << std::string(40, ' ')
      << "CREATION" << std::string(16, ' ')
      << "USED" << std::string(8, ' ')
      << "REFER\n";
  for (auto &s : snaps) {
    out << s.name << std::string(std::max(1, 44 - (int)s.name.size()), ' ')
        << s.creation << std::string(std::max(1, 24 - (int)s.creation.size()), ' ')
        << s.used << std::string(std::max(1, 12 - (int)s.used.size()), ' ')
        << s.refer << "\n";
  }
}

std::string renderTableStr(const std::string &dataset,
                           const std::vector<Entry> &snaps) {
  std::ostringstream ss;
  renderTable(ss, dataset, snaps);
  return ss.str();
}

}
