// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "spec_registry_pure.h"

#include <cctype>
#include <string>

namespace SpecRegistryPure {

namespace {

bool isAlnumDashUnderscore(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

bool segmentHasDotDot(const std::string &s) {
  size_t i = 0;
  while (i < s.size()) {
    size_t j = s.find('/', i);
    if (j == std::string::npos) j = s.size();
    if (j - i == 2 && s[i] == '.' && s[i+1] == '.') return true;
    i = j + 1;
  }
  return false;
}

} // anon

std::string validateName(const std::string &n) {
  if (n.empty()) return "name is empty";
  if (n.size() > 63) return "name too long (>63 chars): '" + n + "'";
  if (n[0] == '-' || n[0] == '.')
    return "name must not start with '-' or '.': '" + n + "'";
  for (char c : n)
    if (!isAlnumDashUnderscore(c))
      return "name contains forbidden char (allowed: [A-Za-z0-9_-]): '" + n + "'";
  return "";
}

std::string validatePath(const std::string &p) {
  if (p.empty()) return "path is empty";
  if (p.size() > 1024) return "path too long: '" + p + "'";
  if (p[0] != '/') return "path must be absolute: '" + p + "'";
  if (segmentHasDotDot(p))
    return "path must not contain '..' segments: '" + p + "'";
  for (char c : p) {
    // Reject control chars, NUL, and a tight set of shell metas.
    // Spaces in path are unusual but legal — we allow them since
    // jails are commonly under /var/run/crate/<name> with no
    // spaces; if an operator stages crates under a weird path
    // they can rename.
    unsigned char uc = static_cast<unsigned char>(c);
    if (uc < 0x20 || uc == 0x7f)
      return "path contains a control character: '" + p + "'";
    if (c == '\\' || c == '"' || c == '\'' || c == '`'
        || c == '$' || c == ';' || c == '|' || c == '&'
        || c == '*' || c == '?' || c == '<' || c == '>'
        || c == '\n' || c == '\r')
      return std::string("path contains forbidden char '") + c + "': '" + p + "'";
  }
  return "";
}

std::string validateEntry(const Entry &e) {
  if (auto err = validateName(e.name);     !err.empty()) return err;
  if (auto err = validatePath(e.cratePath); !err.empty()) return err;
  return "";
}

std::string parseLine(const std::string &line, Entry &out) {
  auto sp = line.find(' ');
  if (sp == std::string::npos) return "no space separator";
  // Reject the operator-typo case of "name<space><space>path"
  // (the path portion must not start with a space). Paths with
  // internal spaces ARE supported because validatePath allows
  // them — split on the first space, take the remainder as path.
  if (sp + 1 < line.size() && line[sp + 1] == ' ')
    return "duplicate separator (use exactly one space between name and path)";
  Entry e;
  e.name      = line.substr(0, sp);
  e.cratePath = line.substr(sp + 1);
  if (auto err = validateEntry(e); !err.empty())
    return err;
  out = e;
  return "";
}

std::string formatLine(const Entry &e) {
  return e.name + " " + e.cratePath;
}

int findIndex(const std::vector<Entry> &entries, const std::string &name) {
  for (size_t i = 0; i < entries.size(); i++)
    if (entries[i].name == name) return (int)i;
  return -1;
}

} // namespace SpecRegistryPure
