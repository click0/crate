// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "wrap_pure.h"
#include "profile_pure.h"

#include <algorithm>
#include <sstream>

namespace WrapPure {

namespace {

constexpr const char *kLauncherMarker = "# crate wrap: ";
constexpr const char *kDesktopKey     = "X-Crate-Profile=";

// Desktop Entry Exec argument: quote when it holds a reserved char.
std::string execArg(const std::string &a) {
  bool plain = !a.empty();
  for (char c : a)
    if (c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '\\' || c == '>' || c == '<' ||
        c == '~' || c == '|' || c == '&' || c == ';' || c == '$' || c == '*' || c == '?' ||
        c == '#' || c == '(' || c == ')' || c == '`')
      plain = false;
  if (plain) return a;
  std::string q = "\"";
  for (char c : a) {
    if (c == '"' || c == '`' || c == '$' || c == '\\') { q += '\\'; q += '\\'; }   // spec: escape for the field, then for the quoting
    if (c == '"' || c == '`' || c == '$' || c == '\\') q += '\\';
    q += c;
  }
  return q + "\"";
}

// sh single quotes
std::string shQuote(const std::string &s) {
  std::string r = "'";
  for (char c : s) {
    if (c == '\'') r += "'\\''";
    else r += c;
  }
  return r + "'";
}

std::string trim(const std::string &s) {
  size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) b++;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) e--;
  return s.substr(b, e - b);
}

}   // namespace

std::string binDir(const std::string &home) { return home + "/.local/bin"; }

std::string applicationsDir(const std::string &home, const std::string &xdgDataHome) {
  if (!xdgDataHome.empty() && xdgDataHome[0] == '/') {
    std::string d = xdgDataHome;
    while (d.size() > 1 && d.back() == '/') d.pop_back();
    return d + "/applications";
  }
  return home + "/.local/share/applications";
}

std::string launcherPath(const std::string &home, const std::string &name) {
  return binDir(home) + "/" + name;
}

std::string desktopFileName(const std::string &profile) { return "crate-" + profile + ".desktop"; }

std::string desktopPath(const std::string &home, const std::string &xdgDataHome,
                        const std::string &profile) {
  return applicationsDir(home, xdgDataHome) + "/" + desktopFileName(profile);
}

std::string validateLauncherName(const std::string &name) {
  if (auto e = ProfilePure::validateProfileName(name); !e.empty()) return "launcher name: " + e;
  if (name == "crate") return "launcher name 'crate' would shadow crate itself";
  return "";
}

std::string renderLauncher(const std::string &profile, const std::string &cratePath,
                           const std::string &version) {
  std::ostringstream s;
  s << "#!/bin/sh\n"
    << kLauncherMarker << profile << " (crate " << version << ")\n"
    << "# Runs the program in its crate container; `crate wrap remove " << profile << "` deletes this file.\n"
    << "exec " << shQuote(cratePath) << " run " << profile << " -- \"$@\"\n";
  return s.str();
}

std::string displayName(const std::string &profile) {
  std::string out;
  bool start = true;
  for (char c : profile) {
    if (c == '-' || c == '_') { out += ' '; start = true; continue; }
    if (start && c >= 'a' && c <= 'z') out += (char)(c - 'a' + 'A');
    else out += c;
    start = false;
  }
  return out + " (crate)";
}

std::string renderDesktop(const std::string &profile, const std::string &cratePath,
                          const std::string &version, bool terminal,
                          const std::string &icon) {
  std::ostringstream s;
  s << "[Desktop Entry]\n"
    << "Type=Application\n"
    << "Version=1.5\n"
    << "Name=" << displayName(profile) << "\n"
    << "Comment=" << profile << " in a crate container (crate " << version << ")\n"
    << "Exec=" << execArg(cratePath) << " run " << profile << " -- %U\n"
    << "Icon=" << (icon.empty() ? profile : icon) << "\n"
    << "Terminal=" << (terminal ? "true" : "false") << "\n"
    << "Categories=X-Crate;\n"
    << kDesktopKey << profile << "\n";
  return s.str();
}

bool launcherProfile(const std::string &content, std::string &profileOut) {
  std::istringstream in(content);
  std::string line;
  int n = 0;
  while (std::getline(in, line) && n++ < 4) {
    if (line.compare(0, std::string(kLauncherMarker).size(), kLauncherMarker) != 0) continue;
    std::string rest = trim(line.substr(std::string(kLauncherMarker).size()));
    size_t sp = rest.find(' ');
    std::string p = sp == std::string::npos ? rest : rest.substr(0, sp);
    if (!ProfilePure::validateProfileName(p).empty()) return false;
    profileOut = p;
    return true;
  }
  return false;
}

bool desktopProfile(const std::string &content, std::string &profileOut) {
  std::istringstream in(content);
  std::string line;
  bool inEntry = false;
  while (std::getline(in, line)) {
    line = trim(line);
    if (line == "[Desktop Entry]") { inEntry = true; continue; }
    if (!line.empty() && line[0] == '[') inEntry = false;
    if (!inEntry) continue;
    if (line.compare(0, std::string(kDesktopKey).size(), kDesktopKey) != 0) continue;
    std::string p = trim(line.substr(std::string(kDesktopKey).size()));
    if (!ProfilePure::validateProfileName(p).empty()) return false;
    profileOut = p;
    return true;
  }
  return false;
}

bool pathHasDir(const std::string &pathEnv, const std::string &dir) {
  auto norm = [](std::string d) {
    while (d.size() > 1 && d.back() == '/') d.pop_back();
    return d;
  };
  const std::string want = norm(dir);
  size_t b = 0;
  while (b <= pathEnv.size()) {
    size_t e = pathEnv.find(':', b);
    if (e == std::string::npos) e = pathEnv.size();
    if (e > b && norm(pathEnv.substr(b, e - b)) == want) return true;
    b = e + 1;
  }
  return false;
}

std::string renderList(const std::vector<Entry> &entries) {
  size_t w = std::string("PROFILE").size();
  for (auto &e : entries) w = std::max(w, e.profile.size());
  std::ostringstream s;
  s << "PROFILE" << std::string(w - 7 + 2, ' ') << "LAUNCHER / DESKTOP\n";
  for (auto &e : entries) {
    std::string pad(w - e.profile.size() + 2, ' ');
    bool first = true;
    for (const std::string *p : {&e.launcher, &e.desktop}) {
      if (p->empty()) continue;
      s << (first ? e.profile + pad : std::string(w + 2, ' ')) << *p << "\n";
      first = false;
    }
    if (first) s << e.profile << pad << "-\n";
  }
  return s.str();
}

}
