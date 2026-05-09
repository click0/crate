// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "per_user_rctl_pure.h"

#include <cctype>

namespace PerUserRctlPure {

namespace {

constexpr const char *kPrefix = "crate-";

std::string uidStr(uint32_t uid) {
  if (uid == 0) return "0";
  std::string out;
  while (uid > 0) {
    out.insert(out.begin(), char('0' + (uid % 10)));
    uid /= 10;
  }
  return out;
}

// Hand-rolled itoa for jids; matches uidStr but accepts signed.
std::string intStr(int n) {
  if (n == 0) return "0";
  std::string out;
  bool neg = n < 0;
  // Use unsigned for the magnitude to avoid INT_MIN abs UB.
  uint32_t m = neg ? (uint32_t)(-(int64_t)n) : (uint32_t)n;
  while (m > 0) {
    out.insert(out.begin(), char('0' + (m % 10)));
    m /= 10;
  }
  if (neg) out.insert(out.begin(), '-');
  return out;
}

} // anon

std::string loginclassName(uint32_t uid) {
  return std::string(kPrefix) + uidStr(uid);
}

std::string jailSubject(int jid) {
  return std::string("jail:") + intStr(jid);
}

std::string loginclassSubject(uint32_t uid) {
  return std::string("loginclass:") + loginclassName(uid);
}

std::string buildRule(const std::string &subject,
                      const std::string &key,
                      const std::string &rawValue) {
  return subject + ":" + key + ":deny=" + rawValue;
}

std::vector<std::string> buildUserUmbrellaRules(
    uint32_t uid, const std::vector<KeyValue> &pairs) {
  std::vector<std::string> out;
  out.reserve(pairs.size());
  std::string subject = loginclassSubject(uid);
  for (const auto &kv : pairs)
    out.push_back(buildRule(subject, kv.key, kv.rawValue));
  return out;
}

std::string validateLoginclassName(const std::string &name) {
  static const std::string prefix = kPrefix;
  if (name.size() <= prefix.size())
    return "loginclass too short — expected '" + prefix + "<uid>'";
  if (name.compare(0, prefix.size(), prefix) != 0)
    return "loginclass missing 'crate-' prefix";
  // Tail must be one or more decimal digits, no leading zero unless
  // the whole tail is "0".
  std::string tail = name.substr(prefix.size());
  if (tail.empty()) return "loginclass missing uid suffix";
  if (tail.size() > 10) return "loginclass uid suffix too long (>10 chars)";
  if (tail.size() > 1 && tail[0] == '0')
    return "loginclass uid suffix has leading zero";
  for (char c : tail) {
    if (!std::isdigit((unsigned char)c))
      return "loginclass uid suffix is not all digits";
  }
  return "";
}

} // namespace PerUserRctlPure
