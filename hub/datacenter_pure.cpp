// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "datacenter_pure.h"

#include <algorithm>
#include <map>
#include <sstream>

namespace DatacenterPure {

std::string validateName(const std::string &name) {
  if (name.empty()) return "datacenter name is empty";
  if (name.size() > 32) return "datacenter name longer than 32 chars";
  for (char c : name) {
    bool ok = (c >= 'a' && c <= 'z')
           || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9')
           || c == '.' || c == '_' || c == '-';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in datacenter name";
      return os.str();
    }
  }
  return "";
}

std::string canonicalName(const std::string &raw) {
  return raw.empty() ? std::string("default") : raw;
}

std::vector<DcSummary> groupAndSummarise(const std::vector<DcView> &views) {
  // Use a map for stable alphabetical ordering by DC name.
  std::map<std::string, DcSummary> by;
  for (auto &v : views) {
    auto key = canonicalName(v.datacenter);
    auto &s = by[key];
    s.name = key;
    s.nodesTotal++;
    if (v.node.reachable) {
      s.nodesReachable++;
      s.containersTotal += v.node.containerCount;
    } else {
      s.nodesDown++;
    }
  }
  std::vector<DcSummary> out;
  out.reserve(by.size());
  for (auto &kv : by) out.push_back(kv.second);
  return out;
}

std::string renderJson(const std::vector<DcSummary> &dcs) {
  std::ostringstream os;
  os << "[";
  for (size_t i = 0; i < dcs.size(); i++) {
    auto &d = dcs[i];
    if (i) os << ",";
    os << "{\"name\":\""        << d.name << "\""
       << ",\"nodes_total\":"     << d.nodesTotal
       << ",\"nodes_reachable\":" << d.nodesReachable
       << ",\"nodes_down\":"      << d.nodesDown
       << ",\"containers_total\":" << d.containersTotal
       << "}";
  }
  os << "]";
  return os.str();
}

} // namespace DatacenterPure
