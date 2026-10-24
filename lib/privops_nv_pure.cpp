// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_nv_pure.h"

#include <cctype>
#include <cstdlib>
#include <cstring>

namespace PrivOpsNvPure {

// --- Generic accessors ---

std::string requireString(const FieldMap &m,
                          const std::string &key,
                          std::string &out) {
  auto it = m.find(key);
  if (it == m.end()) return "missing field '" + key + "'";
  out = it->second;
  return "";
}

std::string requireLong(const FieldMap &m,
                        const std::string &key,
                        long &out) {
  auto it = m.find(key);
  if (it == m.end()) return "missing field '" + key + "'";
  const std::string &s = it->second;
  if (s.empty()) return "field '" + key + "' is empty";
  // Accept optional leading '-' followed by digits. Matches the
  // strictness of PrivOpsWirePure::extractLongField (no decimal
  // point, no whitespace, no thousands separator).
  size_t i = 0;
  if (s[0] == '-') {
    if (s.size() == 1) return "field '" + key + "' is not an integer";
    i = 1;
  }
  for (; i < s.size(); i++) {
    if (!std::isdigit((unsigned char)s[i]))
      return "field '" + key + "' is not an integer";
  }
  out = std::strtol(s.c_str(), nullptr, 10);
  return "";
}

std::string requireUnsigned(const FieldMap &m,
                            const std::string &key,
                            unsigned &out) {
  long v = 0;
  if (auto e = requireLong(m, key, v); !e.empty()) return e;
  if (v < 0) return "field '" + key + "' must be non-negative";
  if (v > 0xFFFFFFFFL)
    return "field '" + key + "' overflows 32-bit unsigned";
  out = (unsigned)v;
  return "";
}

std::string optionalString(const FieldMap &m,
                           const std::string &key,
                           std::string &out) {
  auto it = m.find(key);
  if (it == m.end()) return "";
  out = it->second;
  return "";
}

std::string optionalBool(const FieldMap &m,
                         const std::string &key,
                         bool &out) {
  auto it = m.find(key);
  if (it == m.end()) return "";
  // Accept the canonical strings the listener produces from
  // nvlist booleans, plus the JSON-style equivalents so a future
  // bridge between transports doesn't surprise the parser.
  if (it->second == "true" || it->second == "1") {
    out = true;
    return "";
  }
  if (it->second == "false" || it->second == "0") {
    out = false;
    return "";
  }
  return "field '" + key + "' is not a boolean";
}

// --- Per-verb parsers ---

std::string parseCreateJail(const FieldMap &m,
                            PrivOpsPure::CreateJailReq &out) {
  if (auto e = requireString(m, "name", out.name); !e.empty()) return e;
  if (auto e = requireString(m, "path", out.path); !e.empty()) return e;
  if (auto e = optionalString(m, "hostname", out.hostname); !e.empty()) return e;
  bool b = false;
  if (auto e = optionalBool(m, "vnet", b); !e.empty()) return e;
  if (m.count("vnet")) out.vnet = b;
  if (auto e = optionalString(m, "parameters", out.parameters); !e.empty()) return e;
  return "";
}

std::string parseDestroyJail(const FieldMap &m,
                             PrivOpsPure::DestroyJailReq &out) {
  if (auto e = requireString(m, "name", out.name); !e.empty()) return e;
  bool b = false;
  if (auto e = optionalBool(m, "force", b); !e.empty()) return e;
  if (m.count("force")) out.force = b;
  return "";
}

std::string parseMountNullfs(const FieldMap &m,
                             PrivOpsPure::MountNullfsReq &out) {
  if (auto e = requireString(m, "source", out.source); !e.empty()) return e;
  if (auto e = requireString(m, "target", out.target); !e.empty()) return e;
  bool b = true;
  if (auto e = optionalBool(m, "read_only", b); !e.empty()) return e;
  if (m.count("read_only")) out.readOnly = b;
  return "";
}

std::string parseUnmountNullfs(const FieldMap &m,
                               PrivOpsPure::UnmountNullfsReq &out) {
  if (auto e = requireString(m, "target", out.target); !e.empty()) return e;
  bool b = false;
  if (auto e = optionalBool(m, "force", b); !e.empty()) return e;
  if (m.count("force")) out.force = b;
  return "";
}

std::string parseSetRctl(const FieldMap &m,
                         PrivOpsPure::SetRctlReq &out) {
  if (auto e = requireLong(m, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireString(m, "key", out.key); !e.empty()) return e;
  if (auto e = requireString(m, "value", out.rawValue); !e.empty()) return e;
  return "";
}

std::string parseClearRctl(const FieldMap &m,
                           PrivOpsPure::ClearRctlReq &out) {
  if (auto e = requireLong(m, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireString(m, "key", out.key); !e.empty()) return e;
  return "";
}

std::string parseAttachZfs(const FieldMap &m,
                           PrivOpsPure::AttachZfsReq &out) {
  if (auto e = requireLong(m, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireString(m, "dataset", out.dataset); !e.empty()) return e;
  return "";
}

std::string parseDetachZfs(const FieldMap &m,
                           PrivOpsPure::DetachZfsReq &out) {
  if (auto e = requireLong(m, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireString(m, "dataset", out.dataset); !e.empty()) return e;
  return "";
}

std::string parseConfigureIface(const FieldMap &m,
                                PrivOpsPure::ConfigureIfaceReq &out) {
  if (auto e = requireLong(m, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireString(m, "ifname", out.ifname); !e.empty()) return e;
  if (auto e = optionalString(m, "bridge", out.bridge); !e.empty()) return e;
  if (auto e = optionalString(m, "ipv4_cidr", out.ipv4Cidr); !e.empty()) return e;
  if (auto e = optionalString(m, "ipv6_cidr", out.ipv6Cidr); !e.empty()) return e;
  if (auto e = optionalString(m, "mac_addr", out.macAddr); !e.empty()) return e;
  return "";
}

std::string parseTeardownIface(const FieldMap &m,
                               PrivOpsPure::TeardownIfaceReq &out) {
  if (auto e = requireString(m, "ifname", out.ifname); !e.empty()) return e;
  return "";
}

std::string parseAddPfRule(const FieldMap &m,
                           PrivOpsPure::AddPfRuleReq &out) {
  if (auto e = requireString(m, "anchor", out.anchor); !e.empty()) return e;
  if (auto e = requireString(m, "rule", out.ruleText); !e.empty()) return e;
  return "";
}

std::string parseRemovePfRule(const FieldMap &m,
                              PrivOpsPure::RemovePfRuleReq &out) {
  if (auto e = requireString(m, "anchor", out.anchor); !e.empty()) return e;
  if (auto e = requireString(m, "rule", out.ruleText); !e.empty()) return e;
  return "";
}

std::string parseAddIpfwRule(const FieldMap &m,
                             PrivOpsPure::AddIpfwRuleReq &out) {
  if (auto e = requireUnsigned(m, "set", out.set); !e.empty()) return e;
  if (auto e = requireUnsigned(m, "number", out.number); !e.empty()) return e;
  if (auto e = requireString(m, "action", out.action); !e.empty()) return e;
  if (auto e = requireString(m, "body", out.body); !e.empty()) return e;
  return "";
}

std::string parseRemoveIpfwRule(const FieldMap &m,
                                PrivOpsPure::RemoveIpfwRuleReq &out) {
  if (auto e = requireUnsigned(m, "set", out.set); !e.empty()) return e;
  if (auto e = requireUnsigned(m, "number", out.number); !e.empty()) return e;
  return "";
}

std::string parseSetIfaceUp(const FieldMap &m,
                            PrivOpsPure::SetIfaceUpReq &out) {
  if (auto e = requireString(m, "ifname", out.ifname); !e.empty()) return e;
  return "";
}

std::string parseDisableIfaceOffload(const FieldMap &m,
                                     PrivOpsPure::DisableIfaceOffloadReq &out) {
  if (auto e = requireString(m, "ifname", out.ifname); !e.empty()) return e;
  return "";
}

std::string parseBridgeAddMember(const FieldMap &m,
                                 PrivOpsPure::BridgeAddMemberReq &out) {
  if (auto e = requireString(m, "bridge", out.bridge); !e.empty()) return e;
  if (auto e = requireString(m, "member", out.member); !e.empty()) return e;
  return "";
}

std::string parseBridgeDelMember(const FieldMap &m,
                                 PrivOpsPure::BridgeDelMemberReq &out) {
  if (auto e = requireString(m, "bridge", out.bridge); !e.empty()) return e;
  if (auto e = requireString(m, "member", out.member); !e.empty()) return e;
  return "";
}

std::string parseSetIfaceInetAddr(const FieldMap &m,
                                  PrivOpsPure::SetIfaceInetAddrReq &out) {
  if (auto e = requireString(m, "ifname", out.ifname); !e.empty()) return e;
  if (auto e = optionalBool(m, "inet6", out.inet6); !e.empty()) return e;   // 1.1.57
  if (auto e = requireString(m, "addr", out.addr); !e.empty()) return e;
  if (auto e = requireUnsigned(m, "prefix_len", out.prefixLen); !e.empty()) return e;
  return "";
}

std::string parseCreateEpair(const FieldMap &/*m*/,
                             PrivOpsPure::CreateEpairReq &/*out*/) {
  return "";
}

std::string parseEnsureUserRoot(const FieldMap &/*m*/,
                                PrivOpsPure::EnsureUserRootReq &/*out*/) {
  return "";
}

std::string parseSetLoginclassRctl(const FieldMap &m,
                                   PrivOpsPure::SetLoginclassRctlReq &out) {
  if (auto e = requireString(m, "loginclass", out.loginclass); !e.empty()) return e;
  if (auto e = requireString(m, "key", out.key); !e.empty()) return e;
  if (auto e = requireString(m, "value", out.rawValue); !e.empty()) return e;
  return "";
}

std::string parseClearLoginclassRctl(const FieldMap &m,
                                     PrivOpsPure::ClearLoginclassRctlReq &out) {
  if (auto e = requireString(m, "loginclass", out.loginclass); !e.empty()) return e;
  if (auto e = requireString(m, "key", out.key); !e.empty()) return e;
  return "";
}

std::string parseReclaimIfaceFromVnet(const FieldMap &m,
                                      PrivOpsPure::ReclaimIfaceFromVnetReq &out) {
  if (auto e = requireString(m, "ifname",    out.ifname);   !e.empty()) return e;
  if (auto e = requireString(m, "jail_name", out.jailName); !e.empty()) return e;
  return "";
}

std::string parseFlushPfAnchor(const FieldMap &m,
                               PrivOpsPure::FlushPfAnchorReq &out) {
  if (auto e = requireString(m, "anchor", out.anchor); !e.empty()) return e;
  return "";
}

std::string parseQueryJailRctl(const FieldMap &m,
                               PrivOpsPure::QueryJailRctlReq &out) {
  if (auto e = requireUnsigned(m, "jid", out.jid); !e.empty()) return e;
  if (auto e = optionalBool(m, "limits", out.limits); !e.empty()) return e;   // 1.1.41
  return "";
}

// --- 1.1.41 ---

std::string parseSetIfaceMac(const FieldMap &m,
                             PrivOpsPure::SetIfaceMacReq &out) {
  if (auto e = requireString(m, "ifname", out.ifname); !e.empty()) return e;
  if (auto e = requireString(m, "mac", out.mac); !e.empty()) return e;
  return "";
}

std::string parseDeleteIpfwNat(const FieldMap &m,
                               PrivOpsPure::DeleteIpfwNatReq &out) {
  if (auto e = requireUnsigned(m, "number", out.number); !e.empty()) return e;
  return "";
}

std::string parseCreateBridge(const FieldMap &m,
                              PrivOpsPure::CreateBridgeReq &out) {
  if (auto e = requireString(m, "name", out.name); !e.empty()) return e;
  return "";
}

// --- 1.1.57 ---

std::string parseAcquireFwLease(const FieldMap &m,
                                PrivOpsPure::AcquireFwLeaseReq &out) {
  if (auto e = requireUnsigned(m, "jid", out.jid); !e.empty()) return e;
  if (auto e = optionalBool(m, "slot", out.slot); !e.empty()) return e;
  if (auto e = optionalBool(m, "fwd4", out.fwd4); !e.empty()) return e;
  if (auto e = optionalBool(m, "fwd6", out.fwd6); !e.empty()) return e;
  return "";
}

std::string parseReleaseFwLease(const FieldMap &m,
                                PrivOpsPure::ReleaseFwLeaseReq &out) {
  if (auto e = requireUnsigned(m, "jid", out.jid); !e.empty()) return e;
  return "";
}

std::string parseConfigureIpfwNat(const FieldMap &m,
                                  PrivOpsPure::ConfigureIpfwNatReq &out) {
  if (auto e = requireUnsigned(m, "number", out.number); !e.empty()) return e;
  if (auto e = requireString(m, "config", out.config); !e.empty()) return e;
  return "";
}

std::string parseSetJailCpuset(const FieldMap &m,
                               PrivOpsPure::SetJailCpusetReq &out) {
  if (auto e = requireUnsigned(m, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireString(m, "cpuset", out.cpuset); !e.empty()) return e;
  return "";
}

std::string parseApplyDevfsRuleset(const FieldMap &m,
                                   PrivOpsPure::ApplyDevfsRulesetReq &out) {
  if (auto e = requireString(m, "mount_path", out.mountPath); !e.empty()) return e;
  if (auto e = requireUnsigned(m, "ruleset", out.ruleset); !e.empty()) return e;
  return "";
}

std::string parseAddDevfsUnhideRule(const FieldMap &m,
                                    PrivOpsPure::AddDevfsUnhideRuleReq &out) {
  if (auto e = requireString(m, "mount_path",   out.mountPath);   !e.empty()) return e;
  if (auto e = requireString(m, "path_pattern", out.pathPattern); !e.empty()) return e;
  return "";
}

std::string parseSignalJail(const FieldMap &m,
                            PrivOpsPure::SignalJailReq &out) {
  if (auto e = requireUnsigned(m, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireString(m, "signal", out.signal); !e.empty()) return e;
  return "";
}

std::string parseExecInJail(const FieldMap &m,
                            PrivOpsPure::ExecInJailReq &out) {
  if (auto e = requireUnsigned(m, "jid", out.jid); !e.empty()) return e;
  if (auto e = optionalString(m, "user", out.user); !e.empty()) return e;
  if (auto e = optionalString(m, "term", out.term); !e.empty()) return e;
  unsigned argc = 0;
  if (auto e = requireUnsigned(m, "argc", argc); !e.empty()) return e;
  if (argc == 0) return "field 'argc' must be >= 1";
  if (argc > PrivOpsPure::kExecInJailMaxArgs)
    return "field 'argc' exceeds " + std::to_string(PrivOpsPure::kExecInJailMaxArgs);
  out.argv.clear();
  out.argv.reserve(argc);
  for (unsigned i = 0; i < argc; i++) {
    std::string a;
    if (auto e = requireString(m, "argv" + std::to_string(i), a); !e.empty()) return e;
    out.argv.push_back(std::move(a));
  }
  return "";
}

// 1.1.62
std::string parseApplyDevfsRules(const FieldMap &m,
                                 PrivOpsPure::ApplyDevfsRulesReq &out) {
  if (auto e = requireString(m, "mount_path", out.mountPath); !e.empty()) return e;
  if (auto e = requireUnsigned(m, "ruleset", out.ruleset); !e.empty()) return e;
  unsigned argc = 0;
  if (auto e = requireUnsigned(m, "argc", argc); !e.empty()) return e;
  if (argc == 0) return "field 'argc' must be >= 1";
  if (argc > PrivOpsPure::kApplyDevfsRulesMaxRules)
    return "field 'argc' exceeds " + std::to_string(PrivOpsPure::kApplyDevfsRulesMaxRules);
  out.rules.clear();
  out.rules.reserve(argc);
  for (unsigned i = 0; i < argc; i++) {
    std::string r;
    if (auto e = requireString(m, "rule" + std::to_string(i), r); !e.empty()) return e;
    out.rules.push_back(std::move(r));
  }
  return "";
}

// --- 1.1.43: nvlist header pre-check ---

std::string parseNvlistHeader(const unsigned char *buf, size_t len, NvlistHeader &out) {
  out = NvlistHeader{};
  if (buf == nullptr || len < kNvlistHeaderSize) return "short header";
  if (buf[0] != 0x6c) return "bad nvlist magic";
  if (buf[1] != 0x00) return "unsupported nvlist version";
  const unsigned char flags = buf[2];
  out.bigEndian = (flags & 0x80) != 0;
  auto rd64 = [&](size_t off) -> uint64_t {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++) {
      // libnv writes the header in the *sender's* byte order and marks
      // big-endian senders in flags; decode accordingly.
      size_t idx = out.bigEndian ? off + i : off + (7 - i);
      v = (v << 8) | (uint64_t)buf[idx];
    }
    return v;
  };
  out.descriptors = rd64(3);
  out.size        = rd64(11);
  return "";
}

std::string checkNvlistHeaderLimits(const NvlistHeader &h) {
  if (h.size > kMaxNvlistRequestBytes)
    return "request too large (" + std::to_string(h.size) + " bytes, limit " +
           std::to_string(kMaxNvlistRequestBytes) + ")";
  if (h.descriptors > kMaxNvlistRequestDescriptors)
    return "too many descriptors (" + std::to_string(h.descriptors) + ", limit " +
           std::to_string(kMaxNvlistRequestDescriptors) + ")";
  return "";
}

// --- Verb routing ---

PrivOpsPure::Verb extractVerb(const FieldMap &m) {
  auto it = m.find("verb");
  if (it == m.end()) return PrivOpsPure::Verb::Unknown;
  return PrivOpsPure::parseVerb(it->second);
}

} // namespace PrivOpsNvPure
