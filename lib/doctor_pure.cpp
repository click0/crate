// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "doctor_pure.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace DoctorPure {

const char *severityLabel(Severity s) {
  switch (s) {
  case Severity::Pass: return "PASS";
  case Severity::Warn: return "WARN";
  case Severity::Fail: return "FAIL";
  }
  return "?";
}

Counts tally(const Report &r) {
  Counts c;
  for (const auto &ch : r.checks) {
    switch (ch.severity) {
    case Severity::Pass: c.pass++; break;
    case Severity::Warn: c.warn++; break;
    case Severity::Fail: c.fail++; break;
    }
  }
  return c;
}

Check passCheck(const std::string &category, const std::string &name,
                const std::string &detail) {
  return Check{category, name, Severity::Pass, detail};
}

Check warnCheck(const std::string &category, const std::string &name,
                const std::string &detail) {
  return Check{category, name, Severity::Warn, detail};
}

Check failCheck(const std::string &category, const std::string &name,
                const std::string &detail) {
  return Check{category, name, Severity::Fail, detail};
}

namespace {

// JSON-escape (same shape as audit_pure / control_socket_pure).
std::string jsonEscape(const std::string &s) {
  std::ostringstream o;
  for (unsigned char c : s) {
    switch (c) {
    case '"':  o << "\\\""; break;
    case '\\': o << "\\\\"; break;
    case '\n': o << "\\n";  break;
    case '\r': o << "\\r";  break;
    case '\t': o << "\\t";  break;
    case '\b': o << "\\b";  break;
    case '\f': o << "\\f";  break;
    default:
      if (c < 0x20) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "\\u%04x", (int)c);
        o << buf;
      } else {
        o << (char)c;
      }
    }
  }
  return o.str();
}

// Stable category order so `crate doctor` output diffs cleanly across
// runs. Categories not in this list sort alphabetically after the
// known ones — operators can add their own without us caring.
int categoryRank(const std::string &c) {
  if (c == "kernel")     return 0;
  if (c == "command")    return 1;
  if (c == "filesystem") return 2;
  if (c == "zfs")        return 3;
  if (c == "config")     return 4;
  if (c == "jails")      return 5;
  if (c == "audit")      return 6;
  if (c == "auto-fw")    return 7;  // 0.8.9
  return 100;  // unknown -> after known
}

// ANSI 16-colour codes (matching rang::fg).
const char *colourFor(Severity s, bool noColor) {
  if (noColor) return "";
  switch (s) {
  case Severity::Pass: return "\x1b[32m";  // green
  case Severity::Warn: return "\x1b[33m";  // yellow
  case Severity::Fail: return "\x1b[31m";  // red
  }
  return "";
}
const char *resetColour(bool noColor) {
  return noColor ? "" : "\x1b[0m";
}

} // anon

std::string renderText(const Report &rIn, bool noColor) {
  // Sort checks: by category-rank, then by category name (for unknowns
  // that share rank 100), then by name.
  auto checks = rIn.checks;
  std::stable_sort(checks.begin(), checks.end(),
    [](const Check &a, const Check &b) {
      auto ra = categoryRank(a.category);
      auto rb = categoryRank(b.category);
      if (ra != rb) return ra < rb;
      if (a.category != b.category) return a.category < b.category;
      return a.name < b.name;
    });

  // Compute column widths so output is aligned.
  std::size_t nameW = 0;
  for (const auto &ch : checks)
    if (ch.name.size() > nameW) nameW = ch.name.size();
  if (nameW > 40) nameW = 40;  // hard cap so a pathological name
                               // doesn't blow up the whole layout

  std::ostringstream o;
  std::string lastCategory;
  for (const auto &ch : checks) {
    if (ch.category != lastCategory) {
      if (!lastCategory.empty()) o << "\n";
      o << ch.category << ":\n";
      lastCategory = ch.category;
    }
    o << "  ["
      << colourFor(ch.severity, noColor)
      << severityLabel(ch.severity)
      << resetColour(noColor)
      << "] "
      << std::left << std::setw((int)nameW) << ch.name;
    if (!ch.detail.empty())
      o << "  " << ch.detail;
    o << "\n";
  }
  // Summary
  auto c = tally(rIn);
  o << "\nSummary: "
    << colourFor(Severity::Pass, noColor) << c.pass << " PASS" << resetColour(noColor) << ", "
    << colourFor(Severity::Warn, noColor) << c.warn << " WARN" << resetColour(noColor) << ", "
    << colourFor(Severity::Fail, noColor) << c.fail << " FAIL" << resetColour(noColor) << "\n";
  return o.str();
}

std::string renderJson(const Report &r) {
  std::ostringstream o;
  o << "{\"checks\":[";
  for (std::size_t i = 0; i < r.checks.size(); i++) {
    if (i > 0) o << ",";
    const auto &ch = r.checks[i];
    o << "{\"category\":\""  << jsonEscape(ch.category) << "\","
      << "\"name\":\""        << jsonEscape(ch.name)     << "\","
      << "\"severity\":\""    << severityLabel(ch.severity) << "\","
      << "\"detail\":\""      << jsonEscape(ch.detail)   << "\"}";
  }
  auto c = tally(r);
  o << "],\"summary\":{"
    << "\"pass\":" << c.pass << ","
    << "\"warn\":" << c.warn << ","
    << "\"fail\":" << c.fail << "}}";
  return o.str();
}

int exitCodeFor(const Report &r) {
  auto c = tally(r);
  if (c.fail > 0) return 2;
  if (c.warn > 0) return 1;
  return 0;
}

} // namespace DoctorPure
