// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "lifecycle_pure.h"

#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>

namespace LifecyclePure {

namespace {

// Decimal number right after `key":` (optional whitespace) at or after
// `from`, bounded by `to`. False when absent or not a plain number.
bool numberAfterKey(const std::string &s, size_t from, size_t to,
                    const std::string &key, uint64_t &out) {
  const std::string needle = "\"" + key + "\":";
  size_t p = s.find(needle, from);
  if (p == std::string::npos || p >= to) return false;
  p += needle.size();
  while (p < to && (s[p] == ' ' || s[p] == '\t')) p++;
  if (p >= to || !std::isdigit((unsigned char)s[p])) return false;
  uint64_t v = 0;
  size_t digits = 0;
  while (p < to && std::isdigit((unsigned char)s[p])) {
    const uint64_t d = (uint64_t)(s[p] - '0');
    if (++digits > 20 || v > (UINT64_MAX - d) / 10) return false;   // overflow
    v = v * 10 + d;
    p++;
  }
  out = v;
  return true;
}

} // namespace

bool parseNetstatIfaceBytesJson(const std::string &json, const std::string &iface,
                                uint64_t &ibytes, uint64_t &obytes) {
  if (iface.empty() || json.empty() || json[0] != '{') return false;
  const std::string nameField = "\"name\":\"" + iface + "\"";
  size_t at = json.find(nameField);
  if (at == std::string::npos) return false;
  // The interface object runs from the '{' before "name" to the
  // matching '}' — libxo emits flat objects here, so the next '}' is it.
  size_t objStart = json.rfind('{', at);
  size_t objEnd   = json.find('}', at);
  if (objStart == std::string::npos || objEnd == std::string::npos) return false;
  uint64_t in = 0, out = 0;
  if (!numberAfterKey(json, objStart, objEnd, "received-bytes", in)) return false;
  if (!numberAfterKey(json, objStart, objEnd, "sent-bytes", out)) return false;
  ibytes = in;
  obytes = out;
  return true;
}

} // namespace LifecyclePure

namespace LifecyclePure {

#define LP_STR(x) static_cast<std::ostringstream&&>(std::ostringstream() << x).str()

std::string humanBytes(uint64_t bytes) {
  if (bytes >= (1ULL << 30))
    return LP_STR(std::fixed << std::setprecision(1)
                  << (double)bytes / (1ULL << 30) << "G");
  if (bytes >= (1ULL << 20))
    return LP_STR(std::fixed << std::setprecision(1)
                  << (double)bytes / (1ULL << 20) << "M");
  if (bytes >= (1ULL << 10))
    return LP_STR(std::fixed << std::setprecision(1)
                  << (double)bytes / (1ULL << 10) << "K");
  return LP_STR(bytes << "B");
}

}
