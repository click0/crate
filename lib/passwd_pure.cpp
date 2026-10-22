// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "passwd_pure.h"

#include <algorithm>
#include <sstream>

namespace PasswdPure {

namespace {

std::vector<std::string> splitColons(const std::string &line) {
  std::vector<std::string> f;
  std::string cur;
  for (char c : line) {
    if (c == ':') { f.push_back(cur); cur.clear(); }
    else cur.push_back(c);
  }
  f.push_back(cur);
  return f;
}

bool parseId(const std::string &s, uint32_t &out) {
  if (s.empty() || s.size() > 10) return false;
  uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + (uint64_t)(c - '0');
  }
  if (v > 0xFFFFFFFFull) return false;
  out = (uint32_t)v;
  return true;
}

bool parseEither(const std::string &line, User &out) {
  if (line.empty() || line[0] == '#') return false;
  auto f = splitColons(line);
  if (f.size() == 10) {               // master.passwd(5)
    if (f[0].empty()) return false;
    User u;
    u.name = f[0];
    if (!parseId(f[2], u.uid) || !parseId(f[3], u.gid)) return false;
    u.loginClass = f[4];
    u.home = f[8];
    u.shell = f[9];
    out = std::move(u);
    return true;
  }
  if (f.size() == 7) {                // passwd(5)
    if (f[0].empty()) return false;
    User u;
    u.name = f[0];
    if (!parseId(f[2], u.uid) || !parseId(f[3], u.gid)) return false;
    u.home = f[5];
    u.shell = f[6];
    out = std::move(u);
    return true;
  }
  return false;
}

} // anon

bool parseMasterPasswdLine(const std::string &line, User &out) {
  if (line.empty() || line[0] == '#') return false;
  if (splitColons(line).size() != 10) return false;
  return parseEither(line, out);
}

bool lookupUser(const std::string &content, const std::string &name, User &out) {
  if (name.empty()) return false;
  std::istringstream in(content);
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    User u;
    if (!parseEither(line, u)) continue;
    if (u.name == name) { out = std::move(u); return true; }
  }
  return false;
}

std::vector<uint32_t> supplementaryGroups(const std::string &content,
                                          const std::string &user,
                                          uint32_t primaryGid,
                                          size_t maxGroups) {
  std::vector<uint32_t> groups{primaryGid};
  if (user.empty() || maxGroups <= 1) return groups;
  std::istringstream in(content);
  std::string line;
  while (std::getline(in, line) && groups.size() < maxGroups) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    auto f = splitColons(line);
    if (f.size() != 4) continue;
    uint32_t gid;
    if (!parseId(f[2], gid)) continue;
    bool member = false;
    std::string m;
    std::istringstream members(f[3]);
    while (std::getline(members, m, ',')) {
      if (m == user) { member = true; break; }
    }
    if (!member) continue;
    if (std::find(groups.begin(), groups.end(), gid) == groups.end())
      groups.push_back(gid);
  }
  return groups;
}

}
