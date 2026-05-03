// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ha_pure.h"

#include <set>
#include <sstream>

namespace HaPure {

namespace {

const NodeView *findNode(const std::vector<NodeView> &nodes,
                         const std::string &name) {
  for (auto &n : nodes)
    if (n.name == name) return &n;
  return nullptr;
}

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

bool isValidName(const std::string &s) {
  if (s.empty() || s.size() > 64) return false;
  for (char c : s)
    if (!isAlnum(c) && c != '.' && c != '_' && c != '-')
      return false;
  return true;
}

void appendJsonEscaped(std::ostringstream &os, const std::string &s) {
  for (unsigned char c : s) {
    switch (c) {
      case '"':  os << "\\\""; break;
      case '\\': os << "\\\\"; break;
      case '\b': os << "\\b"; break;
      case '\f': os << "\\f"; break;
      case '\n': os << "\\n"; break;
      case '\r': os << "\\r"; break;
      case '\t': os << "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
          os << buf;
        } else {
          os << static_cast<char>(c);
        }
    }
  }
}

} // anon

std::vector<MigrationOrder>
evaluateFailoverOrders(const std::vector<HaSpec> &specs,
                       const std::vector<NodeView> &nodes,
                       long thresholdSeconds) {
  std::vector<MigrationOrder> orders;
  for (auto &s : specs) {
    auto *primary = findNode(nodes, s.primaryNode);
    if (!primary) continue;                      // primary not in pool
    if (primary->reachable) continue;            // happy path
    if (primary->unreachableSeconds < thresholdSeconds)
      continue;                                  // anti-flap window

    // Find the first partner that's currently reachable.
    for (auto &partnerName : s.partnerNodes) {
      auto *p = findNode(nodes, partnerName);
      if (!p) continue;
      if (!p->reachable) continue;
      MigrationOrder o;
      o.container = s.containerName;
      o.fromNode  = s.primaryNode;
      o.toNode    = partnerName;
      std::ostringstream r;
      r << "primary node '" << s.primaryNode
        << "' down for " << primary->unreachableSeconds
        << "s (>= threshold " << thresholdSeconds << "s)";
      o.reason = r.str();
      orders.push_back(std::move(o));
      break; // one order per spec — first reachable partner wins
    }
    // If we fell off the end with no reachable partner: silently
    // skip. A "no available partner" diagnostic could be added
    // later; for now keeping the orders list strictly actionable.
  }
  return orders;
}

std::string renderOrdersJson(const std::vector<MigrationOrder> &orders) {
  std::ostringstream os;
  os << "[";
  for (size_t i = 0; i < orders.size(); i++) {
    auto &o = orders[i];
    if (i) os << ",";
    os << "{\"container\":\"";
    appendJsonEscaped(os, o.container);
    os << "\",\"from_node\":\"";
    appendJsonEscaped(os, o.fromNode);
    os << "\",\"to_node\":\"";
    appendJsonEscaped(os, o.toNode);
    os << "\",\"reason\":\"";
    appendJsonEscaped(os, o.reason);
    os << "\"}";
  }
  os << "]";
  return os.str();
}

std::string validateSpecs(const std::vector<HaSpec> &specs) {
  for (size_t i = 0; i < specs.size(); i++) {
    auto &s = specs[i];
    auto idx = "ha[" + std::to_string(i) + "]";
    if (!isValidName(s.containerName))
      return idx + ": invalid container name '" + s.containerName + "'";
    if (!isValidName(s.primaryNode))
      return idx + ": invalid primary node name '" + s.primaryNode + "'";
    if (s.partnerNodes.empty())
      return idx + ": at least one partner_nodes entry is required";
    std::set<std::string> seen;
    seen.insert(s.primaryNode);
    for (auto &p : s.partnerNodes) {
      if (!isValidName(p))
        return idx + ": invalid partner node name '" + p + "'";
      if (!seen.insert(p).second)
        return idx + ": partner '" + p + "' duplicated or matches primary";
    }
  }
  return "";
}

} // namespace HaPure
