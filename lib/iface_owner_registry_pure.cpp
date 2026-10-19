// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "iface_owner_registry_pure.h"
#include "privops_authz_pure.h"   // isEpairIfaceName — one definition of the shape

#include <cctype>
#include <sstream>

namespace IfaceOwnerRegistryPure {

namespace {

bool parseDecimal(const std::string &s, uint64_t &out) {
  if (s.empty() || s.size() > 10) return false;
  uint64_t v = 0;
  for (char c : s) {
    if (!std::isdigit((unsigned char)c)) return false;
    v = v * 10 + (uint64_t)(c - '0');
  }
  out = v;
  return true;
}

} // namespace

std::string serialize(const EntryMap &entries) {
  if (entries.empty()) return {};
  std::ostringstream out;
  for (const auto &kv : entries)
    out << kv.first << '\t' << kv.second << '\n';
  return out.str();
}

bool parse(const std::string &text, EntryMap &out, std::string &err) {
  out.clear();
  err.clear();
  size_t lineNo = 0, pos = 0;
  while (pos <= text.size()) {
    auto nl = text.find('\n', pos);
    std::string line = (nl == std::string::npos) ? text.substr(pos)
                                                 : text.substr(pos, nl - pos);
    pos = (nl == std::string::npos) ? text.size() + 1 : nl + 1;
    lineNo++;
    if (line.empty() || line[0] == '#') continue;
    auto tab = line.find('\t');
    if (tab == std::string::npos || tab == 0 ||
        line.find('\t', tab + 1) != std::string::npos) {
      err = "line " + std::to_string(lineNo) + ": expected exactly 2 tab-separated columns";
      out.clear();
      return false;
    }
    std::string name = line.substr(0, tab);
    uint64_t uid = 0;
    if (!isEpairName(name)) {
      err = "line " + std::to_string(lineNo) + ": '" + name + "' is not an epair half";
      out.clear();
      return false;
    }
    if (!parseDecimal(line.substr(tab + 1), uid) || uid > 0xFFFFFFFFu) {
      err = "line " + std::to_string(lineNo) + ": uid out of range";
      out.clear();
      return false;
    }
    if (out.count(name)) {
      err = "line " + std::to_string(lineNo) + ": duplicate interface " + name;
      out.clear();
      return false;
    }
    out.emplace(name, static_cast<uint32_t>(uid));
  }
  return true;
}

bool isEpairName(const std::string &name) {
  return PrivOpsAuthzPure::isEpairIfaceName(name);
}

// The a/b suffix is always the last character of a valid epair name.
std::string peerHalf(const std::string &name) {
  if (!isEpairName(name)) return {};
  std::string peer = name;
  peer.back() = (name.back() == 'a') ? 'b' : 'a';
  return peer;
}

std::string hostHalf(const std::string &name) {
  if (!isEpairName(name)) return {};
  std::string host = name;
  host.back() = 'a';
  return host;
}

size_t reconcile(EntryMap &entries, const LiveProbe &isLive) {
  if (!isLive) return 0;
  size_t dropped = 0;
  for (auto it = entries.begin(); it != entries.end();) {
    const std::string probe = hostHalf(it->first);
    if (probe.empty() || !isLive(probe)) {
      it = entries.erase(it);
      dropped++;
    } else {
      ++it;
    }
  }
  return dropped;
}

} // namespace IfaceOwnerRegistryPure
