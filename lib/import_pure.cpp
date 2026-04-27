// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "import_pure.h"

#include "util.h"   // Util::stripTrailingSpace

#include <sstream>

namespace ImportPure {

std::string parseSha256File(const std::string &line) {
  auto spacePos = line.find(' ');
  auto expectedHash = (spacePos != std::string::npos) ? line.substr(0, spacePos) : line;
  return Util::stripTrailingSpace(expectedHash);
}

bool archiveHasTraversal(const std::string &listing) {
  std::istringstream is(listing);
  std::string entry;
  while (std::getline(is, entry))
    if (entry.find("..") != std::string::npos)
      return true;
  return false;
}

std::string normalizeArchiveEntry(const std::string &entry) {
  std::string name = entry;
  if (name.substr(0, 2) == "./") name = name.substr(2);
  while (!name.empty() && name.back() == '/') name.pop_back();
  return name;
}

}
