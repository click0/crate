// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "retune_pure.h"

#include <cstdio>
#include <set>
#include <sstream>

namespace RetunePure {

namespace {

// Keys that take a percentage value (0..100, no suffix).
const std::set<std::string> &percentKeys() {
  static const std::set<std::string> k = {"pcpu"};
  return k;
}

// Keys that take a byte rate or absolute byte count (K/M/G/T allowed).
const std::set<std::string> &byteKeys() {
  static const std::set<std::string> k = {
    "memoryuse", "vmemoryuse",
    "readbps", "writebps",
    "swapuse", "stacksize", "datasize", "memorylocked",
    "shmsize",
  };
  return k;
}

// Keys that take a plain integer (operations / counts, no suffix).
const std::set<std::string> &intKeys() {
  static const std::set<std::string> k = {
    "readiops", "writeiops",
    "maxproc", "openfiles", "nthr",
    "cpuset",
  };
  return k;
}

bool isAllDigits(const std::string &s) {
  if (s.empty()) return false;
  for (char c : s) if (c < '0' || c > '9') return false;
  return true;
}

bool isInt0to100(const std::string &s) {
  if (!isAllDigits(s)) return false;
  long n = 0;
  for (char c : s) n = n * 10 + (c - '0');
  return n <= 100;
}

bool isHumanSize(const std::string &s) {
  // <integer-or-decimal>[KkMmGgTt]?
  if (s.empty()) return false;
  size_t end = s.size();
  char suf = s.back();
  if (suf == 'K' || suf == 'k' || suf == 'M' || suf == 'm'
   || suf == 'G' || suf == 'g' || suf == 'T' || suf == 't')
    end--;
  if (end == 0) return false;          // suffix only, no digits
  bool sawDot = false, sawDigit = false;
  for (size_t i = 0; i < end; i++) {
    char c = s[i];
    if (c >= '0' && c <= '9') { sawDigit = true; continue; }
    if (c == '.' && !sawDot)  { sawDot = true; continue; }
    return false;
  }
  return sawDigit;
}

} // anon

std::string validateRctlKey(const std::string &key) {
  if (key.empty()) return "rctl key is empty";
  if (percentKeys().count(key) || byteKeys().count(key) || intKeys().count(key))
    return "";
  // Build a help message that points the operator at the supported
  // set instead of just shrugging.
  std::ostringstream os;
  os << "unknown rctl key '" << key << "'; supported: pcpu, "
     << "memoryuse, vmemoryuse, readbps, writebps, readiops, "
     << "writeiops, maxproc, openfiles, nthr, swapuse";
  return os.str();
}

std::string validateRctlValue(const std::string &key,
                              const std::string &rawValue) {
  if (rawValue.empty())
    return "value for '" + key + "' is empty";
  if (rawValue.size() > 32)
    return "value for '" + key + "' is unreasonably long";
  if (percentKeys().count(key)) {
    if (!isInt0to100(rawValue))
      return "value for '" + key + "' must be an integer 0..100, got '" + rawValue + "'";
    return "";
  }
  if (byteKeys().count(key)) {
    if (!isHumanSize(rawValue))
      return "value for '" + key
           + "' must be a number with optional K/M/G/T suffix, got '"
           + rawValue + "'";
    return "";
  }
  if (intKeys().count(key)) {
    if (!isAllDigits(rawValue))
      return "value for '" + key + "' must be a non-negative integer, got '" + rawValue + "'";
    return "";
  }
  // Should not reach (validateRctlKey would have caught it).
  return "value validation: unknown key class for '" + key + "'";
}

std::string validatePairs(const std::vector<RctlPair> &pairs) {
  if (pairs.empty())
    return "at least one --rctl KEY=VALUE pair is required";
  for (size_t i = 0; i < pairs.size(); i++) {
    auto &p = pairs[i];
    if (auto e = validateRctlKey(p.key); !e.empty())
      return "rctl[" + std::to_string(i) + "]: " + e;
    if (auto e = validateRctlValue(p.key, p.rawValue); !e.empty())
      return "rctl[" + std::to_string(i) + "]: " + e;
  }
  return "";
}

long parseHumanSize(const std::string &s) {
  if (s.empty()) return -1;
  long mult = 1;
  std::string body = s;
  switch (body.back()) {
    case 'K': case 'k': mult = 1024L;                          body.pop_back(); break;
    case 'M': case 'm': mult = 1024L * 1024L;                  body.pop_back(); break;
    case 'G': case 'g': mult = 1024L * 1024L * 1024L;          body.pop_back(); break;
    case 'T': case 't': mult = 1024L * 1024L * 1024L * 1024L;  body.pop_back(); break;
    default: break;
  }
  if (body.empty()) return -1;
  // Decimal-point support: "1.5M" → 1.5 * 1048576 = 1572864.
  bool sawDot = false;
  long whole = 0, frac = 0, fracDigits = 0;
  for (char c : body) {
    if (c == '.') {
      if (sawDot) return -1;
      sawDot = true;
      continue;
    }
    if (c < '0' || c > '9') return -1;
    if (!sawDot) {
      whole = whole * 10 + (c - '0');
    } else {
      frac = frac * 10 + (c - '0');
      fracDigits++;
      if (fracDigits > 9) return -1;        // sanity
    }
  }
  long fracDenom = 1;
  for (long i = 0; i < fracDigits; i++) fracDenom *= 10;
  // total = (whole + frac/fracDenom) * mult
  long whole_part = whole * mult;
  long frac_part  = (frac * mult) / fracDenom;
  return whole_part + frac_part;
}

std::vector<std::string> buildSetArgv(int jid, const RctlPair &p) {
  std::ostringstream rule;
  rule << "jail:" << jid << ":" << p.key << ":deny=" << p.rawValue;
  return {"/usr/bin/rctl", "-a", rule.str()};
}

std::vector<std::string> buildClearArgv(int jid, const std::string &key) {
  std::ostringstream rule;
  rule << "jail:" << jid << ":" << key << ":deny";
  return {"/usr/bin/rctl", "-r", rule.str()};
}

std::vector<std::string> buildShowArgv(int jid) {
  return {"/usr/bin/rctl", "-u", "jail:" + std::to_string(jid)};
}

} // namespace RetunePure
