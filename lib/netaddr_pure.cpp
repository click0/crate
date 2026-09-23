// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "netaddr_pure.h"

namespace NetAddrPure {

namespace {

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

} // anon

bool isV4Octet(const std::string &s) {
  if (s.empty() || s.size() > 3) return false;
  for (char c : s) if (c < '0' || c > '9') return false;
  int n = 0;
  for (char c : s) n = n * 10 + (c - '0');
  return n <= 255;
}

bool isV4(const std::string &s) {
  size_t pos = 0;
  for (int i = 0; i < 4; i++) {
    auto dot = s.find('.', pos);
    auto end = (i == 3) ? s.size() : dot;
    if (i < 3 && dot == std::string::npos) return false;
    if (!isV4Octet(s.substr(pos, end - pos))) return false;
    pos = (i == 3) ? s.size() : (dot + 1);
  }
  return pos == s.size();
}

bool isV6(const std::string &s) {
  if (s.empty()) return false;
  bool sawDoubleColon = false;
  bool prevGroup = false;     // was the previous token a hex group?
  size_t i = 0;
  int groups = 0;
  while (i < s.size()) {
    if (i + 1 < s.size() && s[i] == ':' && s[i + 1] == ':') {
      if (sawDoubleColon) return false;
      sawDoubleColon = true;
      prevGroup = false;
      i += 2;
      continue;
    }
    if (s[i] == ':') {
      // 1.1.30: a single ':' separates TWO groups — it needs a group
      // right before it (rejects "1:::2") and something after it
      // (rejects a trailing "1:2:3:4:5:6:7:8:").
      if (!prevGroup || i + 1 >= s.size()) return false;
      prevGroup = false;
      i++;
      continue;
    }
    int hexLen = 0;
    while (i < s.size() && hexLen < 4 &&
           ((s[i] >= '0' && s[i] <= '9') ||
            (s[i] >= 'a' && s[i] <= 'f') ||
            (s[i] >= 'A' && s[i] <= 'F'))) {
      i++; hexLen++;
    }
    if (hexLen == 0) return false;
    // 1.1.30: a group must end at ':' or end-of-string. The five former
    // copies stopped after 4 hex digits and started a NEW group on the
    // next digit with no separator, so "12345::1" parsed as 1234,5,1 and
    // 32 bare hex digits passed as a full address.
    if (i < s.size() && s[i] != ':') return false;
    groups++;
    prevGroup = true;
  }
  if (sawDoubleColon) return groups <= 7;
  return groups == 8;
}

bool looksLikeV4Shape(const std::string &s) {
  if (s.empty()) return false;
  bool sawDot = false;
  for (char c : s) {
    if (c == '.') { sawDot = true; continue; }
    if (c < '0' || c > '9') return false;
  }
  return sawDot;
}

bool isHostname(const std::string &s) {
  if (s.empty() || s.size() > 253) return false;
  size_t i = 0;
  while (i < s.size()) {
    size_t labelStart = i;
    while (i < s.size() && s[i] != '.') i++;
    auto label = s.substr(labelStart, i - labelStart);
    if (label.empty() || label.size() > 63) return false;
    if (!isAlnum(label.front()) || !isAlnum(label.back())) return false;
    for (char c : label)
      if (!isAlnum(c) && c != '-') return false;
    if (i < s.size()) i++;
  }
  return true;
}

}
