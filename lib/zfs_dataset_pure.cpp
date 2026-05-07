// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "zfs_dataset_pure.h"

#include <cctype>
#include <regex>
#include <sstream>

namespace ZfsDatasetPure {

std::string pickLatestBackupSuffix(const std::string &zfsListOutput) {
  std::string out;
  std::istringstream is(zfsListOutput);
  std::string line;
  // Match anything ending in @backup-* (the snapshot path before
  // '@' is the dataset name; we don't constrain it here so a
  // recursive zfs list with descendant snapshots still works).
  std::regex re(R"(^.+@(backup-.+)$)");
  while (std::getline(is, line)) {
    // Strip CR for Windows-edited / kernel-pipe outputs.
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    std::smatch m;
    if (std::regex_match(line, m, re)) {
      auto suffix = m[1].str();
      if (suffix > out) out = suffix;
    }
  }
  return out;
}

std::string validateDatasetName(const std::string &ds) {
  if (ds.empty()) return "dataset name is empty";
  if (ds.size() > 255) return "dataset name too long (>255): '" + ds + "'";
  if (ds.front() == '/' || ds.back() == '/')
    return "dataset must not start or end with '/': '" + ds + "'";
  // Reject `..` path segments (defence-in-depth against operator-
  // built dataset strings sneaking through to zfs(8) shell args).
  size_t i = 0;
  while (i < ds.size()) {
    size_t j = ds.find('/', i);
    if (j == std::string::npos) j = ds.size();
    if (j - i == 2 && ds[i] == '.' && ds[i+1] == '.')
      return "dataset must not contain '..' segments: '" + ds + "'";
    i = j + 1;
  }
  for (char c : ds) {
    if (std::isalnum(static_cast<unsigned char>(c))) continue;
    if (c == '_' || c == '-' || c == '.' || c == '/' || c == ':') continue;
    return "dataset contains forbidden char (allowed: [A-Za-z0-9_.:/-]): '"
         + ds + "'";
  }
  return "";
}

} // namespace ZfsDatasetPure
