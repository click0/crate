// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "jid_owner_registry_pure.h"

#include <cctype>
#include <sstream>

namespace JidOwnerRegistryPure {

namespace {

// strtoul without locale / errno noise. Returns false on overflow,
// non-digit, or empty input. Used for the jid and uid columns.
bool parseDecimal(const std::string &s, uint64_t &out) {
  if (s.empty()) return false;
  uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    uint64_t nv = v * 10 + (c - '0');
    if (nv < v) return false;          // overflow
    v = nv;
  }
  out = v;
  return true;
}

// Split `line` on tabs into exactly 4 tokens. Returns false otherwise.
// We deliberately don't allow empty fields (every column is mandatory).
bool splitTabs4(const std::string &line, std::string out[4]) {
  size_t pos = 0;
  for (int i = 0; i < 3; i++) {
    auto tab = line.find('\t', pos);
    if (tab == std::string::npos) return false;
    out[i] = line.substr(pos, tab - pos);
    if (out[i].empty()) return false;
    pos = tab + 1;
  }
  out[3] = line.substr(pos);
  if (out[3].empty()) return false;
  // Reject embedded tab in the last field — that means there were >4
  // columns.
  return out[3].find('\t') == std::string::npos;
}

} // namespace

std::string serialize(const EntryMap &entries) {
  if (entries.empty()) return {};
  std::ostringstream out;
  for (const auto &kv : entries) {
    out << kv.first << '\t'
        << kv.second.uid << '\t'
        << kv.second.name << '\t'
        << kv.second.path << '\n';
  }
  return out.str();
}

bool parse(const std::string &text, EntryMap &out, std::string &err) {
  out.clear();
  err.clear();
  size_t lineNo = 0;
  size_t pos = 0;
  while (pos <= text.size()) {
    auto nl = text.find('\n', pos);
    std::string line = (nl == std::string::npos)
                           ? text.substr(pos)
                           : text.substr(pos, nl - pos);
    pos = (nl == std::string::npos) ? text.size() + 1 : nl + 1;
    lineNo++;
    if (line.empty() || line[0] == '#') continue;   // blank / comment

    std::string col[4];
    if (!splitTabs4(line, col)) {
      err = "line " + std::to_string(lineNo) +
            ": expected exactly 4 tab-separated columns";
      out.clear();
      return false;
    }

    uint64_t jidNum = 0, uidNum = 0;
    if (!parseDecimal(col[0], jidNum) || jidNum == 0 || jidNum > 0xFFFFu) {
      err = "line " + std::to_string(lineNo) + ": jid must be 1..65535";
      out.clear();
      return false;
    }
    if (!parseDecimal(col[1], uidNum) || uidNum > 0xFFFFFFFFu) {
      err = "line " + std::to_string(lineNo) + ": uid out of range";
      out.clear();
      return false;
    }
    // We don't re-validate name/path here — they were validated by the
    // privops layer at create_jail time; the on-disk form only ever
    // contains values that already passed the upstream validators. A
    // hand-edited file with a bad name will still load but won't match
    // any incoming verb.
    unsigned jid = static_cast<unsigned>(jidNum);
    if (out.count(jid)) {
      err = "line " + std::to_string(lineNo) +
            ": duplicate jid " + std::to_string(jid);
      out.clear();
      return false;
    }
    Entry e;
    e.uid  = static_cast<uint32_t>(uidNum);
    e.name = col[2];
    e.path = col[3];
    out.emplace(jid, std::move(e));
  }
  return true;
}

bool lookupByName(const EntryMap &entries, const std::string &name,
                  unsigned &jidOut, Entry &entryOut) {
  for (const auto &kv : entries) {
    if (kv.second.name == name) {
      jidOut    = kv.first;
      entryOut  = kv.second;
      return true;
    }
  }
  return false;
}

bool findOwnerByPath(const EntryMap &entries, const std::string &query,
                     unsigned &jidOut, Entry &entryOut) {
  // Slash-anchored prefix match — same shape as PrivOpsAuthzPure::
  // datasetOwned() uses for ZFS prefixes. Among all matches, pick the
  // entry with the LONGEST path so nested jails resolve to the inner
  // one rather than its parent.
  bool found = false;
  size_t bestLen = 0;
  for (const auto &kv : entries) {
    const std::string &p = kv.second.path;
    if (p.empty()) continue;                   // defensive
    const bool exact      = (query == p);
    const bool descendant = (query.size() > p.size()
                          && query.compare(0, p.size(), p) == 0
                          && query[p.size()] == '/');
    if (!exact && !descendant) continue;
    if (!found || p.size() > bestLen) {
      found    = true;
      bestLen  = p.size();
      jidOut   = kv.first;
      entryOut = kv.second;
    }
  }
  return found;
}

} // namespace JidOwnerRegistryPure
