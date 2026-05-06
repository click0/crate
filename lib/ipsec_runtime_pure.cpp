// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ipsec_runtime_pure.h"

namespace IpsecRuntimePure {

namespace {

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

} // anon

std::string validateConnName(const std::string &name) {
  if (name.empty()) return "ipsec conn name is empty";
  if (name.size() > 32) return "ipsec conn name longer than 32 chars";
  // Reserved by strongSwan as a fallthrough block.
  if (name == "%default") return "ipsec conn name '%default' is reserved by strongSwan";
  for (char c : name) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-';
    if (!ok) {
      std::string msg = "invalid character '";
      msg += c;
      msg += "' in ipsec conn name";
      return msg;
    }
  }
  return "";
}

namespace {

std::vector<std::string> buildAutoArgv(const std::string &verb,
                                       const std::string &connName) {
  return {"/usr/local/sbin/ipsec", "auto", verb, connName};
}

} // anon

std::vector<std::string> buildAddArgv(const std::string &connName) {
  return buildAutoArgv("--add", connName);
}

std::vector<std::string> buildUpArgv(const std::string &connName) {
  return buildAutoArgv("--up", connName);
}

std::vector<std::string> buildDownArgv(const std::string &connName) {
  return buildAutoArgv("--down", connName);
}

std::vector<std::string> buildDeleteArgv(const std::string &connName) {
  return buildAutoArgv("--delete", connName);
}

bool isEnabled(const std::string &connName) {
  return !connName.empty();
}

} // namespace IpsecRuntimePure
