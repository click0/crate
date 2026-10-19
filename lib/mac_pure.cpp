// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "mac_pure.h"

#include <algorithm>
#include <sstream>

namespace MacPure {

std::string formatPortaclRule(int uid, const std::string &proto, int port) {
  std::ostringstream ss;
  ss << "uid:" << uid << ":" << proto << ":" << port;
  return ss.str();
}

std::vector<std::string> splitPortaclRules(const std::string &value) {
  std::vector<std::string> out;
  std::string cur;
  auto flush = [&]() {
    size_t b = cur.find_first_not_of(" \t\n");
    size_t e = cur.find_last_not_of(" \t\n");
    if (b != std::string::npos) out.push_back(cur.substr(b, e - b + 1));
    cur.clear();
  };
  for (char c : value) {
    if (c == ',') flush();
    else cur.push_back(c);
  }
  flush();
  return out;
}

static std::string join(const std::vector<std::string> &rules) {
  std::string out;
  for (const auto &r : rules) {
    if (!out.empty()) out += ',';
    out += r;
  }
  return out;
}

std::string mergePortaclRules(const std::string &current,
                              const std::vector<std::string> &ours) {
  auto rules = splitPortaclRules(current);
  for (const auto &r : ours) {
    if (r.empty()) continue;
    if (std::find(rules.begin(), rules.end(), r) == rules.end())
      rules.push_back(r);
  }
  return join(rules);
}

std::string removePortaclRules(const std::string &current,
                               const std::vector<std::string> &ours) {
  auto rules = splitPortaclRules(current);
  std::vector<std::string> kept;
  for (const auto &r : rules)
    if (std::find(ours.begin(), ours.end(), r) == ours.end())
      kept.push_back(r);
  return join(kept);
}

} // namespace MacPure
