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

std::vector<std::string> snapshotSuffixes(const std::string &zfsListOutput,
                                          const std::string &dataset,
                                          const std::string &prefix) {
  std::vector<std::string> out;
  if (dataset.empty()) return out;
  const std::string head = dataset + "@" + prefix;
  std::istringstream is(zfsListOutput);
  std::string line;
  while (std::getline(is, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
      line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    if (line.compare(0, head.size(), head) != 0) continue;
    auto suffix = line.substr(dataset.size() + 1);
    if (suffix.size() <= prefix.size()) continue;   // a bare "@backup-" is not a snapshot of ours
    if (suffix.find('/') != std::string::npos || suffix.find('@') != std::string::npos) continue;
    out.push_back(suffix);
  }
  return out;
}

std::string pickLatestSuffix(const std::string &zfsListOutput,
                             const std::string &dataset,
                             const std::string &prefix) {
  std::string out;
  for (auto &s : snapshotSuffixes(zfsListOutput, dataset, prefix))
    if (s > out) out = s;
  return out;
}

std::string pickLatestCommonSuffix(const std::string &localOut, const std::string &localDataset,
                                   const std::string &remoteOut, const std::string &remoteDataset,
                                   const std::vector<std::string> &prefixes) {
  std::string best, bestBody;
  for (auto &prefix : prefixes) {
    if (prefix.empty()) continue;
    auto remote = snapshotSuffixes(remoteOut, remoteDataset, prefix);
    for (auto &s : snapshotSuffixes(localOut, localDataset, prefix)) {
      bool onRemote = false;
      for (auto &r : remote) if (r == s) { onRemote = true; break; }
      if (!onRemote) continue;
      auto body = s.substr(prefix.size());
      if (body > bestBody) { bestBody = body; best = s; }
    }
  }
  return best;
}

namespace {

std::string uidStr(uint32_t uid) {
  if (uid == 0) return "0";
  std::string out;
  while (uid > 0) {
    out.insert(out.begin(), char('0' + (uid % 10)));
    uid /= 10;
  }
  return out;
}

} // anon

std::string composePerUserPrefix(const std::string &masterPrefix,
                                 uint32_t uid) {
  // Strip a single trailing slash for nice composition; reject
  // leading slash by leaving it (validateDatasetName on the
  // result will catch it for the caller).
  std::string base = masterPrefix;
  if (!base.empty() && base.back() == '/') base.pop_back();
  return base + "/" + uidStr(uid);
}

std::string composePerUserDataset(const std::string &masterPrefix,
                                  uint32_t uid,
                                  const std::string &jailName) {
  return composePerUserPrefix(masterPrefix, uid) + "/" + jailName;
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
