// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "throttle_pure.h"

#include <sstream>

namespace ThrottlePure {

namespace {

bool isAllDigits(const std::string &s) {
  if (s.empty()) return false;
  for (char c : s) if (c < '0' || c > '9') return false;
  return true;
}

bool isV4Octet(const std::string &s) {
  if (s.empty() || s.size() > 3) return false;
  for (char c : s) if (c < '0' || c > '9') return false;
  int n = 0;
  for (char c : s) n = n * 10 + (c - '0');
  return n <= 255;
}

bool endsWith(const std::string &s, const std::string &suf) {
  if (s.size() < suf.size()) return false;
  return s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

bool numericPrefixOk(const std::string &s, size_t bodyLen) {
  // Accept integer or decimal: "10", "1.5". Body must be ≥1 char.
  if (bodyLen == 0) return false;
  bool sawDot = false, sawDigit = false;
  for (size_t i = 0; i < bodyLen; i++) {
    char c = s[i];
    if (c >= '0' && c <= '9') { sawDigit = true; continue; }
    if (c == '.' && !sawDot)  { sawDot = true; continue; }
    return false;
  }
  return sawDigit;
}

} // anon

std::string validateRate(const std::string &rate) {
  if (rate.empty()) return "rate is empty";
  if (rate.size() > 32) return "rate is unreasonably long";
  // Try the bit/s suffixes first.
  for (auto suf : {"Kbit/s", "Mbit/s", "Gbit/s"})
    if (endsWith(rate, suf)) {
      auto bodyLen = rate.size() - std::string(suf).size();
      if (!numericPrefixOk(rate, bodyLen))
        return "rate body must be a number, got '" + rate + "'";
      return "";
    }
  // Then byte/s suffixes (uppercase B is mandatory).
  for (auto suf : {"KB/s", "MB/s", "GB/s"})
    if (endsWith(rate, suf)) {
      auto bodyLen = rate.size() - std::string(suf).size();
      if (!numericPrefixOk(rate, bodyLen))
        return "rate body must be a number, got '" + rate + "'";
      return "";
    }
  // Plain bytes/s (integer only — no decimal for raw bytes).
  if (isAllDigits(rate)) return "";
  return "rate must be 'NK?bit/s', 'NK?B/s', or a plain integer (bytes/s); got '" + rate + "'";
}

std::string validateBurst(const std::string &burst) {
  if (burst.empty()) return "";          // empty = no burst
  if (burst.size() > 32) return "burst is unreasonably long";
  for (auto suf : {"KB", "MB", "GB"})
    if (endsWith(burst, suf)) {
      auto bodyLen = burst.size() - std::string(suf).size();
      if (!numericPrefixOk(burst, bodyLen))
        return "burst body must be a number, got '" + burst + "'";
      return "";
    }
  if (isAllDigits(burst)) return "";
  return "burst must be 'NK?B' or a plain integer (bytes); got '" + burst + "'";
}

std::string validateQueue(const std::string &queue) {
  if (queue.empty()) return "";          // empty = dummynet default
  if (queue.size() > 32) return "queue is unreasonably long";
  // Slot count: plain integer 1..1000.
  if (isAllDigits(queue)) {
    long n = 0;
    for (char c : queue) n = n * 10 + (c - '0');
    if (n < 1 || n > 1000)
      return "queue (slot count) must be 1..1000";
    return "";
  }
  // Or byte size: "100KB", "1MB"
  for (auto suf : {"KB", "MB"})
    if (endsWith(queue, suf)) {
      auto bodyLen = queue.size() - std::string(suf).size();
      if (!numericPrefixOk(queue, bodyLen))
        return "queue body must be a number, got '" + queue + "'";
      return "";
    }
  return "queue must be a slot count (1..1000) or 'NK?B'; got '" + queue + "'";
}

std::string validateIp(const std::string &ip) {
  if (ip.empty()) return "jail IP is empty";
  if (ip.size() > 15) return "jail IP longer than 15 chars";
  size_t pos = 0;
  for (int i = 0; i < 4; i++) {
    auto dot = ip.find('.', pos);
    auto end = (i == 3) ? ip.size() : dot;
    if (i < 3 && dot == std::string::npos) return "jail IP missing octet";
    if (!isV4Octet(ip.substr(pos, end - pos)))
      return "jail IP has invalid octet";
    pos = (i == 3) ? ip.size() : (dot + 1);
  }
  if (pos != ip.size()) return "jail IP has trailing data";
  return "";
}

unsigned pipeIdForJail(int jid, bool egress) {
  // Two pipes per jail; allocations stable across daemon restarts.
  // jid * 2 + (egress ? 1 : 0), offset by kPipeBase.
  return kPipeBase + (unsigned)(jid * 2) + (egress ? 1u : 0u);
}

unsigned ruleIdForJail(int jid, bool egress) {
  return kRuleBase + (unsigned)(jid * 2) + (egress ? 1u : 0u);
}

std::string validateSpec(const ThrottleSpec &s) {
  if (!s.ingressRate.empty())
    if (auto e = validateRate(s.ingressRate); !e.empty())
      return "ingress rate: " + e;
  if (!s.egressRate.empty())
    if (auto e = validateRate(s.egressRate); !e.empty())
      return "egress rate: " + e;
  if (auto e = validateBurst(s.ingressBurst); !e.empty())
    return "ingress burst: " + e;
  if (auto e = validateBurst(s.egressBurst); !e.empty())
    return "egress burst: " + e;
  if (auto e = validateQueue(s.queue); !e.empty())
    return "queue: " + e;
  // Burst without rate is a no-op — flag it so the operator
  // notices the typo instead of seeing zero effect.
  if (!s.ingressBurst.empty() && s.ingressRate.empty())
    return "ingress burst given without ingress rate";
  if (!s.egressBurst.empty() && s.egressRate.empty())
    return "egress burst given without egress rate";
  return "";
}

bool hasAnyThrottle(const ThrottleSpec &s) {
  return !s.ingressRate.empty() || !s.egressRate.empty();
}

std::vector<std::string> buildPipeConfigArgv(unsigned pipeId,
                                              const std::string &rate,
                                              const std::string &burst,
                                              const std::string &queue) {
  std::vector<std::string> a = {
    "/sbin/ipfw", "pipe", std::to_string(pipeId), "config",
    "bw", rate,
  };
  if (!burst.empty()) {
    a.push_back("burst");
    a.push_back(burst);
  }
  if (!queue.empty()) {
    a.push_back("queue");
    a.push_back(queue);
  }
  return a;
}

std::vector<std::string> buildBindArgv(unsigned ruleId,
                                        unsigned pipeId,
                                        const std::string &jailIp,
                                        bool egress) {
  // Egress: traffic FROM the jail's IP TO any destination.
  // Ingress: traffic FROM any source TO the jail's IP.
  if (egress) {
    return {"/sbin/ipfw", "add", std::to_string(ruleId),
            "pipe", std::to_string(pipeId),
            "ip", "from", jailIp, "to", "any", "out"};
  }
  return {"/sbin/ipfw", "add", std::to_string(ruleId),
          "pipe", std::to_string(pipeId),
          "ip", "from", "any", "to", jailIp, "in"};
}

std::vector<std::string> buildRuleDeleteArgv(unsigned ruleId) {
  return {"/sbin/ipfw", "delete", std::to_string(ruleId)};
}

std::vector<std::string> buildPipeDeleteArgv(unsigned pipeId) {
  return {"/sbin/ipfw", "pipe", std::to_string(pipeId), "delete"};
}

std::vector<std::string> buildPipeShowArgv(unsigned pipeId) {
  return {"/sbin/ipfw", "pipe", "show", std::to_string(pipeId)};
}

} // namespace ThrottlePure
