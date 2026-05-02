// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "aggregator_pure.h"

#include <sstream>

namespace AggregatorPure {

Summary summarise(const std::vector<NodeView> &nodes) {
  Summary s;
  s.nodesTotal = (unsigned)nodes.size();
  for (auto &n : nodes) {
    if (n.reachable) {
      s.nodesReachable++;
      s.containersTotal += n.containerCount;
    } else {
      s.nodesDown++;
    }
  }
  return s;
}

std::string renderSummaryJson(const Summary &s) {
  std::ostringstream os;
  os << "{"
     << "\"nodes_total\":"      << s.nodesTotal
     << ",\"nodes_reachable\":" << s.nodesReachable
     << ",\"nodes_down\":"      << s.nodesDown
     << ",\"containers_total\":" << s.containersTotal
     << "}";
  return os.str();
}

unsigned countTopLevelObjects(const std::string &json) {
  // Strip surrounding whitespace.
  size_t a = 0, b = json.size();
  while (a < b && (json[a] == ' ' || json[a] == '\t' || json[a] == '\n' || json[a] == '\r')) a++;
  while (b > a && (json[b-1] == ' ' || json[b-1] == '\t' || json[b-1] == '\n' || json[b-1] == '\r')) b--;
  if (b - a < 2) return 0;
  if (json[a] != '[' || json[b - 1] != ']') return 0;

  unsigned count = 0;
  int depth = 0;
  bool inString = false;
  bool escape = false;
  // Track whether we have seen any non-whitespace inside this top-level
  // array element so an empty array yields 0.
  bool seenContent = false;
  for (size_t i = a + 1; i < b - 1; i++) {
    char c = json[i];
    if (escape) { escape = false; continue; }
    if (inString) {
      if (c == '\\') escape = true;
      else if (c == '"') inString = false;
      continue;
    }
    if (c == '"') { inString = true; seenContent = true; continue; }
    if (c == '{') {
      if (depth == 0) count++;
      depth++;
      seenContent = true;
    } else if (c == '}') {
      if (depth > 0) depth--;
    } else if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != ',') {
      seenContent = true;
    }
  }
  if (depth != 0 || inString) return 0;
  if (!seenContent) return 0;
  return count;
}

} // namespace AggregatorPure
