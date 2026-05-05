// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "backup_prune_pure.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <set>
#include <sstream>
#include <unordered_map>

namespace BackupPrunePure {

namespace {

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

// True if every char in s is decimal digit.
bool allDigits(const std::string &s) {
  if (s.empty()) return false;
  for (char c : s) if (c < '0' || c > '9') return false;
  return true;
}

// strict timegm(3) replacement using mktime+TZ trick is racy; do the
// math by hand. UTC-only, no DST. Year >= 1970.
long civilToEpoch(int y, int m, int d, int hh, int mm, int ss) {
  // Days from 1970-01-01 to <y>-<m>-<d>, by Howard Hinnant's algorithm.
  // (see http://howardhinnant.github.io/date_algorithms.html#days_from_civil)
  y -= (m <= 2);
  const long era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  long days = era * 146097L + static_cast<long>(doe) - 719468L;
  return days * 86400L + hh * 3600L + mm * 60L + ss;
}

} // anon

std::string validateDir(const std::string &dir) {
  // Same shape as BackupPure::validateOutputDir.
  if (dir.empty()) return "directory is empty";
  if (dir.size() > 1024) return "directory longer than 1024 chars";
  if (dir.front() != '/') return "directory must be absolute";
  // hand-rolled '..' segment detection
  size_t i = 0;
  while (i < dir.size()) {
    auto slash = dir.find('/', i);
    auto end = (slash == std::string::npos) ? dir.size() : slash;
    if (dir.substr(i, end - i) == "..")
      return "directory must not contain '..' segments";
    if (slash == std::string::npos) break;
    i = slash + 1;
  }
  for (char c : dir) {
    if (c == ';' || c == '`' || c == '$' || c == '|' || c == '&'
        || c == '<' || c == '>' || c == '\\' || c == '\n' || c == '\r'
        || c == '*' || c == '?' || c == '"' || c == '\'')
      return "directory contains shell metacharacters";
  }
  return "";
}

std::string validateJailFilter(const std::string &name) {
  if (name.empty()) return "";
  return BackupPure::validateJailName(name);
}

long parseSuffixEpoch(const std::string &suffix) {
  // Expected: "backup-YYYY-MM-DDTHH:MM:SSZ"  (length = 7+20 = 27)
  static const char kPrefix[] = "backup-";
  const size_t kPrefixLen = sizeof(kPrefix) - 1;
  if (suffix.size() != kPrefixLen + 20) return 0;
  if (suffix.compare(0, kPrefixLen, kPrefix) != 0) return 0;
  const std::string body = suffix.substr(kPrefixLen);
  // body: "YYYY-MM-DDTHH:MM:SSZ"
  if (body.size() != 20) return 0;
  if (body[4] != '-' || body[7] != '-' || body[10] != 'T'
      || body[13] != ':' || body[16] != ':' || body[19] != 'Z')
    return 0;
  auto y_s = body.substr(0, 4);
  auto m_s = body.substr(5, 2);
  auto d_s = body.substr(8, 2);
  auto hh_s = body.substr(11, 2);
  auto mm_s = body.substr(14, 2);
  auto ss_s = body.substr(17, 2);
  if (!allDigits(y_s) || !allDigits(m_s) || !allDigits(d_s)
      || !allDigits(hh_s) || !allDigits(mm_s) || !allDigits(ss_s))
    return 0;
  int y = std::atoi(y_s.c_str());
  int m = std::atoi(m_s.c_str());
  int d = std::atoi(d_s.c_str());
  int hh = std::atoi(hh_s.c_str());
  int mm = std::atoi(mm_s.c_str());
  int ss = std::atoi(ss_s.c_str());
  if (y < 1970 || y > 9999) return 0;
  if (m < 1 || m > 12) return 0;
  if (d < 1 || d > 31) return 0;
  if (hh > 23 || mm > 59 || ss > 60) return 0;
  long e = civilToEpoch(y, m, d, hh, mm, ss);
  if (e <= 0) return 0;
  return e;
}

bool parseStreamFilename(const std::string &basename,
                         StreamFile &out,
                         std::string &errOut) {
  errOut.clear();
  out = StreamFile{};

  // Must end in .zstream.
  static const char kExt[] = ".zstream";
  const size_t kExtLen = sizeof(kExt) - 1;
  if (basename.size() <= kExtLen) {
    errOut = "filename too short for .zstream suffix";
    return false;
  }
  if (basename.compare(basename.size() - kExtLen, kExtLen, kExt) != 0) {
    errOut = "filename does not end in .zstream";
    return false;
  }
  std::string stem = basename.substr(0, basename.size() - kExtLen);

  // Optional ".inc-from-<incFromSuffix>" tail.
  static const char kIncTag[] = ".inc-from-";
  const size_t kIncTagLen = sizeof(kIncTag) - 1;
  std::string incFrom;
  size_t incPos = stem.find(kIncTag);
  if (incPos != std::string::npos) {
    incFrom = stem.substr(incPos + kIncTagLen);
    stem = stem.substr(0, incPos);
  }

  // Now: stem == "<jail>-backup-YYYY-MM-DDTHH:MM:SSZ"
  // Find "-backup-" boundary.
  static const char kBackupTag[] = "-backup-";
  size_t bp = stem.rfind(kBackupTag);
  if (bp == std::string::npos || bp == 0) {
    errOut = "filename does not contain '-backup-' separator";
    return false;
  }
  std::string jail = stem.substr(0, bp);
  std::string suffix = stem.substr(bp + 1);  // strip the leading '-' so suffix == "backup-..."

  // Jail name validation: alnum + . _ -, length 1..64. Same alphabet
  // as BackupPure::validateJailName but inlined here so we don't make
  // parsing depend on the validator's error-message text.
  if (jail.empty() || jail.size() > 64) {
    errOut = "jail name out of length bounds";
    return false;
  }
  for (char c : jail) {
    if (!(isAlnum(c) || c == '.' || c == '_' || c == '-')) {
      errOut = "jail name contains invalid character";
      return false;
    }
  }

  // Validate the suffix shape.
  long epoch = parseSuffixEpoch(suffix);
  if (epoch == 0) {
    errOut = "snapshot suffix is not a valid 'backup-<utc-iso8601>'";
    return false;
  }

  // Validate incFrom suffix if present (must also be parseable; an
  // unparseable inc-from string is a corrupt filename).
  if (!incFrom.empty()) {
    if (parseSuffixEpoch(incFrom) == 0) {
      errOut = "inc-from-<suffix> is not a valid 'backup-<utc-iso8601>'";
      return false;
    }
  }

  out.filename       = basename;
  out.jailName       = jail;
  out.suffix         = suffix;
  out.incFromSuffix  = incFrom;
  out.unixEpoch      = epoch;
  return true;
}

long hourBucket(long epoch)  { return epoch / 3600L; }
long dayBucket(long epoch)   { return epoch / 86400L; }
long weekBucket(long epoch)  { return epoch / (86400L * 7L); }

long monthBucket(long epoch) {
  // Calendar-aligned: gmtime → year*12 + (month-1).
  // Months don't have uniform length so plain integer division would
  // drift over the years.
  time_t t = static_cast<time_t>(epoch);
  std::tm tm{};
  ::gmtime_r(&t, &tm);
  return static_cast<long>(tm.tm_year + 1900) * 12L
       + static_cast<long>(tm.tm_mon);   // tm_mon is 0..11
}

namespace {

// Walk fulls newest -> oldest, keep newest-per-bucket-key, stop when
// we've seen N distinct buckets. Returns the set of file indices to
// keep (referencing the original `files` vector).
std::set<size_t> bucketKeep(const std::vector<StreamFile> &files,
                            const std::vector<size_t> &fullsByEpochDesc,
                            unsigned n,
                            long (*bucketFn)(long)) {
  std::set<size_t> kept;
  if (n == 0) return kept;
  std::set<long> seen;
  for (size_t idx : fullsByEpochDesc) {
    long key = bucketFn(files[idx].unixEpoch);
    if (seen.find(key) != seen.end()) continue;
    seen.insert(key);
    kept.insert(idx);
    if (seen.size() >= n) break;
  }
  return kept;
}

} // anon

PruneDecision decidePrune(const std::vector<StreamFile> &files,
                          const BackupPure::RetentionPolicy &policy,
                          bool deleteOrphans) {
  PruneDecision d;

  // Partition: indices of fulls with valid epoch, sorted desc by epoch.
  std::vector<size_t> fullsByEpochDesc;
  std::vector<size_t> incrementals;
  std::vector<size_t> badEpoch;             // epoch == 0 (unparseable)
  for (size_t i = 0; i < files.size(); i++) {
    const auto &f = files[i];
    if (f.unixEpoch == 0) {
      badEpoch.push_back(i);
      continue;
    }
    if (f.incFromSuffix.empty())
      fullsByEpochDesc.push_back(i);
    else
      incrementals.push_back(i);
  }
  std::sort(fullsByEpochDesc.begin(), fullsByEpochDesc.end(),
            [&](size_t a, size_t b) {
              return files[a].unixEpoch > files[b].unixEpoch;
            });

  // Apply each bucket policy.
  std::set<size_t> kept;
  auto addAll = [&](const std::set<size_t> &s) {
    for (auto i : s) kept.insert(i);
  };
  addAll(bucketKeep(files, fullsByEpochDesc, policy.hourly,  hourBucket));
  addAll(bucketKeep(files, fullsByEpochDesc, policy.daily,   dayBucket));
  addAll(bucketKeep(files, fullsByEpochDesc, policy.weekly,  weekBucket));
  addAll(bucketKeep(files, fullsByEpochDesc, policy.monthly, monthBucket));

  // Build suffix -> kept-full set so we can decide incrementals.
  std::set<std::string> keptSuffixes;
  for (auto i : kept) keptSuffixes.insert(files[i].suffix);

  // Walk fulls: keep -> kept; otherwise -> remove.
  for (size_t i : fullsByEpochDesc) {
    if (kept.find(i) != kept.end())
      d.keep.push_back(files[i].filename);
    else
      d.remove.push_back(files[i].filename);
  }

  // Walk incrementals: kept iff their base full is kept; otherwise
  // orphan. With --delete-orphans, orphans go to remove instead.
  for (size_t i : incrementals) {
    const auto &f = files[i];
    if (keptSuffixes.find(f.incFromSuffix) != keptSuffixes.end()) {
      d.keep.push_back(f.filename);
    } else {
      if (deleteOrphans)
        d.remove.push_back(f.filename);
      else
        d.orphans.push_back(f.filename);
    }
  }

  // Files with unparseable epoch: never auto-remove (they may be from
  // an external tool the operator put in the same dir). Treat as
  // orphans. With --delete-orphans we still don't touch them — we
  // don't know what they are.
  for (size_t i : badEpoch) {
    d.orphans.push_back(files[i].filename);
  }

  std::sort(d.keep.begin(), d.keep.end());
  std::sort(d.remove.begin(), d.remove.end());
  std::sort(d.orphans.begin(), d.orphans.end());
  return d;
}

std::vector<KeepReason> explainKeeps(const std::vector<StreamFile> &files,
                                     const BackupPure::RetentionPolicy &policy) {
  std::vector<KeepReason> out;
  std::vector<size_t> fullsByEpochDesc;
  for (size_t i = 0; i < files.size(); i++) {
    if (files[i].unixEpoch != 0 && files[i].incFromSuffix.empty())
      fullsByEpochDesc.push_back(i);
  }
  std::sort(fullsByEpochDesc.begin(), fullsByEpochDesc.end(),
            [&](size_t a, size_t b) {
              return files[a].unixEpoch > files[b].unixEpoch;
            });

  struct B { const char *name; unsigned n; long (*fn)(long); };
  B buckets[] = {
    {"hourly",  policy.hourly,  hourBucket},
    {"daily",   policy.daily,   dayBucket},
    {"weekly",  policy.weekly,  weekBucket},
    {"monthly", policy.monthly, monthBucket},
  };

  for (const auto &b : buckets) {
    if (b.n == 0) continue;
    std::set<long> seen;
    unsigned counter = 0;
    for (size_t idx : fullsByEpochDesc) {
      long key = b.fn(files[idx].unixEpoch);
      if (seen.find(key) != seen.end()) continue;
      seen.insert(key);
      counter++;
      KeepReason kr;
      kr.fileIndex = idx;
      std::ostringstream o;
      o << b.name << ":" << counter;
      kr.reason = o.str();
      out.push_back(kr);
      if (seen.size() >= b.n) break;
    }
  }
  return out;
}

} // namespace BackupPrunePure
