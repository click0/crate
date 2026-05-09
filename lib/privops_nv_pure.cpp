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

// --- Verb routing ---

PrivOpsPure::Verb extractVerb(const FieldMap &m) {
  auto it = m.find("verb");
  if (it == m.end()) return PrivOpsPure::Verb::Unknown;
  return PrivOpsPure::parseVerb(it->second);
}

} // namespace PrivOpsNvPure
