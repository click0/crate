// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "auto_fw_pure.h"

#include <sstream>

namespace AutoFwPure {

namespace {

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

} // anon

std::string validateExternalIface(const std::string &iface) {
  if (iface.empty()) return "external interface is empty";
  if (iface.size() > 15) return "external interface name longer than 15 chars (FreeBSD IFNAMSIZ)";
  for (char c : iface) {
    bool ok = isAlnum(c) || c == '.' || c == '_';
    if (!ok)
      return "external interface contains invalid character '" + std::string(1, c) + "'";
  }
  return "";
}

std::string validateRuleAddress(const std::string &addr) {
  if (addr.empty()) return "rule address is empty";
  if (addr.size() > 18) return "rule address longer than 18 chars (max '255.255.255.255/32')";
  bool sawSlash = false;
  for (char c : addr) {
    if (c == '/') {
      if (sawSlash) return "rule address has more than one '/'";
      sawSlash = true;
      continue;
    }
    bool ok = (c >= '0' && c <= '9') || c == '.';
    if (!ok)
      return "rule address contains invalid character '" + std::string(1, c) + "'";
  }
  return "";
}

std::string formatSnatRule(const std::string &externalIface,
                           const std::string &jailAddr) {
  std::ostringstream o;
  o << "nat on " << externalIface
    << " inet from " << jailAddr
    << " to ! " << jailAddr
    << " -> (" << externalIface << ")";
  return o.str();
}

std::string formatSnatAnchorLine(const std::string &externalIface,
                                 const std::string &jailAddr) {
  return formatSnatRule(externalIface, jailAddr) + "\n";
}

// --- Port-forward (rdr) ---

std::string validateProto(const std::string &proto) {
  if (proto.empty()) return "proto is empty";
  if (proto != "tcp" && proto != "udp")
    return "proto must be 'tcp' or 'udp', got '" + proto + "'";
  return "";
}

std::string validatePort(unsigned port) {
  if (port == 0)     return "port 0 is invalid";
  if (port > 65535)  return "port " + std::to_string(port) + " > 65535";
  return "";
}

namespace {

std::string formatPortToken(unsigned lo, unsigned hi) {
  if (lo == hi) return std::to_string(lo);
  std::ostringstream o;
  o << lo << ":" << hi;
  return o.str();
}

} // anon

std::string formatRdrRule(const std::string &externalIface,
                          const std::string &proto,
                          unsigned hostPortLo, unsigned hostPortHi,
                          const std::string &jailAddr,
                          unsigned jailPortLo, unsigned jailPortHi) {
  std::ostringstream o;
  o << "rdr on " << externalIface
    << " inet proto " << proto
    << " from any to (" << externalIface << ")"
    << " port " << formatPortToken(hostPortLo, hostPortHi)
    << " -> " << jailAddr
    << " port " << formatPortToken(jailPortLo, jailPortHi);
  return o.str();
}

std::string formatRdrAnchorLine(const std::string &externalIface,
                                const std::string &proto,
                                unsigned hostPortLo, unsigned hostPortHi,
                                const std::string &jailAddr,
                                unsigned jailPortLo, unsigned jailPortHi) {
  return formatRdrRule(externalIface, proto, hostPortLo, hostPortHi,
                       jailAddr, jailPortLo, jailPortHi) + "\n";
}

// --- ipfw alternative backend ---

namespace {

// Reserved high-number ranges (matches throttle's 10000/20000 bases).
constexpr unsigned kIpfwNatBase           = 30000;
constexpr unsigned kIpfwRuleBase          = 40000;
constexpr unsigned kIpfwLoopbackRuleBase  = 41000;  // 0.8.39 (bug#239590)
constexpr unsigned kIpfwIdMax             = 65535;  // ipfw rule numbers are 16-bit

} // anon

unsigned natIdForJail(int jid) {
  // Cast through unsigned so a negative jid (which shouldn't happen
  // in practice) doesn't underflow the base.
  unsigned u = static_cast<unsigned>(jid);
  return kIpfwNatBase + u;
}

unsigned ruleIdForJail(int jid) {
  unsigned u = static_cast<unsigned>(jid);
  return kIpfwRuleBase + u;
}

unsigned loopbackRuleIdForJail(int jid) {
  // 0.8.39 (bug#239590): host-loopback NAT rule. Sits in 41000+
  // to keep the main nat-activation rule (40000+jid) and the
  // loopback hairpin rule visually distinct in `ipfw -q list`.
  unsigned u = static_cast<unsigned>(jid);
  return kIpfwLoopbackRuleBase + u;
}

std::string validateIpfwNatId(unsigned id) {
  if (id < kIpfwNatBase) return "ipfw NAT id below 30000 reserved range";
  if (id > kIpfwIdMax)   return "ipfw NAT id exceeds 16-bit max";
  return "";
}

std::vector<std::string> buildIpfwNatConfigArgv(unsigned natId,
                                                const std::string &externalIface) {
  return {"/sbin/ipfw", "nat", std::to_string(natId),
          "config", "if", externalIface};
}

std::vector<std::string> buildIpfwNatConfigWithRedirsArgv(
    unsigned natId,
    const std::string &externalIface,
    const std::vector<RedirPort> &redirs) {
  auto argv = buildIpfwNatConfigArgv(natId, externalIface);
  for (const auto &r : redirs) {
    // ipfw redir_port format:
    //   redir_port <proto> <jailIp>:<jailLo>[-<jailHi>] <hostLo>[-<hostHi>]
    argv.push_back("redir_port");
    argv.push_back(r.proto);
    std::string jailPortToken =
      (r.jailPortLo == r.jailPortHi)
        ? std::to_string(r.jailPortLo)
        : (std::to_string(r.jailPortLo) + "-" + std::to_string(r.jailPortHi));
    argv.push_back(r.jailAddr + ":" + jailPortToken);
    std::string hostPortToken =
      (r.hostPortLo == r.hostPortHi)
        ? std::to_string(r.hostPortLo)
        : (std::to_string(r.hostPortLo) + "-" + std::to_string(r.hostPortHi));
    argv.push_back(hostPortToken);
  }
  return argv;
}

std::vector<std::string> buildIpfwNatRuleArgv(unsigned ruleId,
                                              unsigned natId,
                                              const std::string &jailAddr,
                                              const std::string &externalIface) {
  return {"/sbin/ipfw", "add", std::to_string(ruleId),
          "nat", std::to_string(natId),
          "ip", "from", jailAddr, "to", "any",
          "out", "via", externalIface};
}

std::vector<std::string> buildIpfwRuleDeleteArgv(unsigned ruleId) {
  return {"/sbin/ipfw", "delete", std::to_string(ruleId)};
}

std::vector<std::string> buildIpfwNatDeleteArgv(unsigned natId) {
  return {"/sbin/ipfw", "nat", std::to_string(natId), "delete"};
}

std::vector<std::string> buildIpfwHostLoopbackNatArgv(unsigned ruleId,
                                                     unsigned natId) {
  // 0.8.39 (bug#239590): hairpin NAT rule for host-loopback traffic.
  // Reproducer: jail listens on 8080 with `inbound-tcp: 8080`;
  // external LAN clients connect fine, but `nc <host-LAN-IP> 8080`
  // FROM THE HOST ITSELF gets connection-refused.
  //
  // Why: the NAT-activation rule is `from <jail> to any out via em0`
  // for outbound, plus `redir_port` config that reverse-translates
  // incoming traffic on em0. Host-self packets to the host's LAN IP
  // never traverse em0 — the kernel routes them through lo0 — so
  // neither rule fires, packet hits the host's local TCP stack on
  // port 8080 (unbound), gets RST.
  //
  // Fix: this extra rule catches `from me to me` TCP and runs it
  // through the same NAT instance. The redir_port table inside
  // that NAT then matches dst-port and rewrites destination
  // address+port to the jail. udp host-loopback is intentionally
  // not handled here — operators rarely need it; tracked for a
  // followup if a real ask comes in.
  return {"/sbin/ipfw", "add", std::to_string(ruleId),
          "nat", std::to_string(natId),
          "tcp", "from", "me", "to", "me"};
}

namespace {

// Parse the leading whitespace-separated token of `line` as an
// unsigned integer. Returns -1 on non-digit / empty input.
long parseLeadingNumber(const std::string &line) {
  if (line.empty()) return -1;
  size_t i = 0;
  // Skip leading whitespace (rare in `ipfw -q list` output but be
  // defensive for `ipfw list` without -q).
  while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) i++;
  if (i >= line.size() || line[i] < '0' || line[i] > '9') return -1;
  long n = 0;
  while (i < line.size() && line[i] >= '0' && line[i] <= '9') {
    n = n * 10 + (line[i] - '0');
    i++;
    if (n > 99999) return -1;   // ipfw rule numbers are 5-digit max
  }
  return n;
}

} // anon

std::vector<unsigned> pickOrphanIpfwRulesByJid(
  const std::string &ipfwListOutput,
  const std::set<int> &runningJids) {
  std::vector<unsigned> orphans;
  std::istringstream is(ipfwListOutput);
  std::string line;
  while (std::getline(is, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    long n = parseLeadingNumber(line);
    if (n < 40000 || n >= 50000) continue;
    // 0.8.39: range 40000-49999 covers BOTH the main NAT-activation
    // rule (40000+jid) and the host-loopback hairpin rule (41000+jid).
    // For each, recover jid via modulo 1000 and skip rules whose jid
    // doesn't map back into either base — those would be stray rules
    // an operator added in our reserved range, not crate-managed.
    int jid = -1;
    if (n >= 41000 && n < 42000)       jid = static_cast<int>(n) - 41000;
    else if (n >= 40000 && n < 41000)  jid = static_cast<int>(n) - 40000;
    else                               continue;
    if (runningJids.count(jid) == 0)
      orphans.push_back(static_cast<unsigned>(n));
  }
  return orphans;
}

std::vector<unsigned> pickOrphanIpfwThrottleRulesByJid(
  const std::string &ipfwListOutput,
  const std::set<int> &runningJids) {
  std::vector<unsigned> orphans;
  std::istringstream is(ipfwListOutput);
  std::string line;
  while (std::getline(is, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    long n = parseLeadingNumber(line);
    if (n < 20000 || n >= 30000) continue;
    // Throttle uses pairs (20000+jid*2, 20000+jid*2+1) — derive
    // jid by dividing the offset by 2 (integer division).
    int jid = (static_cast<int>(n) - 20000) / 2;
    if (runningJids.count(jid) == 0)
      orphans.push_back(static_cast<unsigned>(n));
  }
  return orphans;
}

std::vector<unsigned> pickOrphanIpfwNatIds(
  const std::string &ipfwNatListOutput,
  const std::set<int> &runningJids) {
  // `ipfw nat list` output (per FreeBSD 13+):
  //   ipfw nat 30001 config if em0 redir_port tcp 10.66.0.1:80 8080
  //   ipfw nat 30002 config if em0
  // The interesting token is the 3rd whitespace-separated field.
  std::vector<unsigned> orphans;
  std::istringstream is(ipfwNatListOutput);
  std::string line;
  while (std::getline(is, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    // Tokenize first 3 fields.
    std::istringstream ls(line);
    std::string tok1, tok2, tok3;
    if (!(ls >> tok1 >> tok2 >> tok3)) continue;
    if (tok1 != "ipfw" || tok2 != "nat") continue;
    long n = -1;
    if (!tok3.empty()) {
      n = 0;
      bool digits = true;
      for (char c : tok3) {
        if (c < '0' || c > '9') { digits = false; break; }
        n = n * 10 + (c - '0');
        if (n > 99999) { digits = false; break; }
      }
      if (!digits) n = -1;
    }
    if (n < 30000 || n >= 40000) continue;
    int jid = static_cast<int>(n) - 30000;
    if (runningJids.count(jid) == 0)
      orphans.push_back(static_cast<unsigned>(n));
  }
  return orphans;
}

} // namespace AutoFwPure
