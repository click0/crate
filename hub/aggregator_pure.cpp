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

// --- 1.1.49 ---

namespace {

// Position just past the matching ']' of the array starting at `open`
// (json[open] == '['), honouring strings. npos when unbalanced.
size_t arrayEnd(const std::string &json, size_t open) {
  int depth = 0; bool inStr = false, esc = false;
  for (size_t i = open; i < json.size(); i++) {
    char c = json[i];
    if (esc) { esc = false; continue; }
    if (inStr) { if (c == '\\') esc = true; else if (c == '"') inStr = false; continue; }
    if (c == '"') { inStr = true; continue; }
    if (c == '[' || c == '{') depth++;
    else if (c == ']' || c == '}') { depth--; if (depth == 0) return i + 1; }
  }
  return std::string::npos;
}

// Value start after `"key":` at or after `from`; npos when absent.
size_t valueAfterKey(const std::string &json, const std::string &key, size_t from) {
  const std::string needle = "\"" + key + "\"";
  size_t p = json.find(needle, from);
  if (p == std::string::npos) return std::string::npos;
  p = json.find(':', p + needle.size());
  if (p == std::string::npos) return std::string::npos;
  p++;
  while (p < json.size() && (json[p] == ' ' || json[p] == '\t' || json[p] == '\n' || json[p] == '\r')) p++;
  return p;
}

std::string arrayAt(const std::string &json, size_t p) {
  if (p == std::string::npos || p >= json.size() || json[p] != '[') return {};
  size_t e = arrayEnd(json, p);
  if (e == std::string::npos) return {};
  return json.substr(p, e - p);
}

} // namespace

std::string extractContainerArray(const std::string &body) {
  size_t a = 0;
  while (a < body.size() && (body[a] == ' ' || body[a] == '\t' || body[a] == '\n' || body[a] == '\r')) a++;
  if (a >= body.size()) return "[]";
  if (body[a] == '[') {
    auto arr = arrayAt(body, a);
    return arr.empty() ? "[]" : arr;
  }
  if (body[a] != '{') return "[]";
  // {"status":..,"data": ...}
  size_t d = valueAfterKey(body, "data", a);
  size_t searchFrom = (d == std::string::npos) ? a : d;
  if (d != std::string::npos && d < body.size() && body[d] == '[') {
    auto arr = arrayAt(body, d);
    return arr.empty() ? "[]" : arr;
  }
  // jls --libxo json: {"jail-information":{"jail":[...]}}
  size_t ji = valueAfterKey(body, "jail-information", searchFrom);
  if (ji != std::string::npos) {
    size_t j = valueAfterKey(body, "jail", ji);
    auto arr = arrayAt(body, j);
    if (!arr.empty()) return arr;
  }
  return "[]";
}

bool splitHostPort(const std::string &spec, std::string &host, int &port, int defaultPort) {
  host.clear(); port = defaultPort;
  if (spec.empty()) return false;
  std::string portStr;
  if (spec[0] == '[') {                       // [v6]:port or [v6]
    size_t close = spec.find(']');
    if (close == std::string::npos) return false;
    host = spec.substr(1, close - 1);
    if (close + 1 < spec.size()) {
      if (spec[close + 1] != ':') return false;
      portStr = spec.substr(close + 2);
      if (portStr.empty()) return false;
    }
  } else if (spec.find(':') != std::string::npos && spec.find(':') != spec.rfind(':')) {
    host = spec;                              // bare IPv6 literal, no port
  } else {
    size_t c = spec.rfind(':');
    if (c == std::string::npos) host = spec;
    else { host = spec.substr(0, c); portStr = spec.substr(c + 1); if (portStr.empty()) return false; }
  }
  if (host.empty()) return false;
  if (!portStr.empty()) {
    if (portStr.size() > 5) return false;
    long v = 0;
    for (char c : portStr) { if (c < '0' || c > '9') return false; v = v * 10 + (c - '0'); }
    if (v < 1 || v > 65535) return false;
    port = (int)v;
  }
  return true;
}

} // namespace AggregatorPure
