// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_pure.h"

#include "per_user_rctl_pure.h"
#include "retune_pure.h"

#include <cctype>
#include <cstdlib>
#include <sstream>

namespace PrivOpsPure {

namespace {

// --- Helpers shared by validators ---

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

bool isHexDigit(char c) {
  return (c >= '0' && c <= '9')
      || (c >= 'a' && c <= 'f')
      || (c >= 'A' && c <= 'F');
}

// Closed list of characters we treat as shell metas at the IPC
// boundary. Conservative on purpose — even though privops are
// supposed to flow through execv (no shell), defence in depth
// catches a future regression where someone wires a verb to
// system(3).
bool hasShellMetachar(const std::string &s) {
  for (char c : s) {
    if (c == ';' || c == '`' || c == '$' || c == '|' || c == '&'
        || c == '<' || c == '>' || c == '\\' || c == '\n' || c == '\r'
        || c == '*' || c == '?' || c == '"' || c == '\'')
      return true;
  }
  return false;
}

bool hasDotDotSegment(const std::string &p) {
  size_t i = 0;
  while (i < p.size()) {
    auto slash = p.find('/', i);
    auto end = (slash == std::string::npos) ? p.size() : slash;
    if (p.substr(i, end - i) == "..") return true;
    if (slash == std::string::npos) break;
    i = slash + 1;
  }
  return false;
}

bool parseUnsignedDec(const std::string &s, unsigned long &out) {
  if (s.empty()) return false;
  unsigned long acc = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    unsigned long n = (unsigned long)(c - '0');
    if (acc > (~0UL - n) / 10) return false; // overflow
    acc = acc * 10 + n;
  }
  out = acc;
  return true;
}

} // anon

// --- Verb name <-> token ---

const char *verbName(Verb v) {
  switch (v) {
    case Verb::CreateJail:      return "create_jail";
    case Verb::DestroyJail:     return "destroy_jail";
    case Verb::MountNullfs:     return "mount_nullfs";
    case Verb::UnmountNullfs:   return "unmount_nullfs";
    case Verb::SetRctl:         return "set_rctl";
    case Verb::ClearRctl:       return "clear_rctl";
    case Verb::AttachZfs:       return "attach_zfs";
    case Verb::DetachZfs:       return "detach_zfs";
    case Verb::ConfigureIface:  return "configure_iface";
    case Verb::TeardownIface:   return "teardown_iface";
    case Verb::AddPfRule:       return "add_pf_rule";
    case Verb::RemovePfRule:    return "remove_pf_rule";
    case Verb::AddIpfwRule:     return "add_ipfw_rule";
    case Verb::RemoveIpfwRule:  return "remove_ipfw_rule";
    case Verb::SetIfaceUp:           return "set_iface_up";
    case Verb::DisableIfaceOffload:  return "disable_iface_offload";
    case Verb::BridgeAddMember:      return "bridge_add_member";
    case Verb::BridgeDelMember:      return "bridge_del_member";
    case Verb::SetIfaceInetAddr:     return "set_iface_inet_addr";
    case Verb::CreateEpair:          return "create_epair";
    case Verb::SetLoginclassRctl:    return "set_loginclass_rctl";
    case Verb::ClearLoginclassRctl:  return "clear_loginclass_rctl";
    case Verb::ReclaimIfaceFromVnet: return "reclaim_iface_from_vnet";
    case Verb::Unknown:         return "unknown";
  }
  return "unknown";
}

Verb parseVerb(const std::string &name) {
  if (name == "create_jail")       return Verb::CreateJail;
  if (name == "destroy_jail")      return Verb::DestroyJail;
  if (name == "mount_nullfs")      return Verb::MountNullfs;
  if (name == "unmount_nullfs")    return Verb::UnmountNullfs;
  if (name == "set_rctl")          return Verb::SetRctl;
  if (name == "clear_rctl")        return Verb::ClearRctl;
  if (name == "attach_zfs")        return Verb::AttachZfs;
  if (name == "detach_zfs")        return Verb::DetachZfs;
  if (name == "configure_iface")   return Verb::ConfigureIface;
  if (name == "teardown_iface")    return Verb::TeardownIface;
  if (name == "add_pf_rule")       return Verb::AddPfRule;
  if (name == "remove_pf_rule")    return Verb::RemovePfRule;
  if (name == "add_ipfw_rule")     return Verb::AddIpfwRule;
  if (name == "remove_ipfw_rule")  return Verb::RemoveIpfwRule;
  if (name == "set_iface_up")           return Verb::SetIfaceUp;
  if (name == "disable_iface_offload")  return Verb::DisableIfaceOffload;
  if (name == "bridge_add_member")      return Verb::BridgeAddMember;
  if (name == "bridge_del_member")      return Verb::BridgeDelMember;
  if (name == "set_iface_inet_addr")    return Verb::SetIfaceInetAddr;
  if (name == "create_epair")           return Verb::CreateEpair;
  if (name == "set_loginclass_rctl")    return Verb::SetLoginclassRctl;
  if (name == "clear_loginclass_rctl")  return Verb::ClearLoginclassRctl;
  if (name == "reclaim_iface_from_vnet") return Verb::ReclaimIfaceFromVnet;
  return Verb::Unknown;
}

// --- Field-level validators ---

std::string validateJailName(const std::string &name) {
  if (name.empty()) return "jail name is empty";
  if (name.size() > 64) return "jail name longer than 64 chars";
  if (name == "." || name == "..") return "jail name is reserved";
  for (char c : name) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in jail name";
      return os.str();
    }
  }
  return "";
}

std::string validateHostname(const std::string &h) {
  if (h.empty()) return ""; // empty = inherit
  if (h.size() > 253) return "hostname longer than 253 chars";
  // labels separated by dots, each label 1..63, alnum or hyphen,
  // not starting or ending with hyphen.
  size_t labelStart = 0;
  for (size_t i = 0; i <= h.size(); i++) {
    bool atDot = (i == h.size()) || h[i] == '.';
    if (!atDot) {
      char c = h[i];
      bool ok = isAlnum(c) || c == '-';
      if (!ok) {
        std::ostringstream os;
        os << "invalid character '" << c << "' in hostname";
        return os.str();
      }
      continue;
    }
    size_t labelLen = i - labelStart;
    if (labelLen == 0) return "empty label in hostname";
    if (labelLen > 63) return "hostname label longer than 63 chars";
    if (h[labelStart] == '-' || h[i - 1] == '-')
      return "hostname label starts or ends with hyphen";
    labelStart = i + 1;
  }
  return "";
}

std::string validateAbsolutePath(const std::string &p) {
  if (p.empty()) return "path is empty";
  if (p.size() > 1024) return "path longer than 1024 chars";
  if (p.front() != '/') return "path must be absolute";
  if (hasDotDotSegment(p))
    return "path must not contain '..' segments";
  if (hasShellMetachar(p))
    return "path contains shell metacharacters";
  return "";
}

std::string validateZfsDataset(const std::string &ds) {
  if (ds.empty()) return "dataset is empty";
  if (ds.size() > 255) return "dataset longer than 255 chars";
  if (ds.front() == '/') return "dataset must not start with '/'";
  if (ds.back() == '/') return "dataset must not end with '/'";
  if (ds.find("//") != std::string::npos)
    return "dataset must not contain '//'";
  for (char c : ds) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-' || c == '/' || c == ':';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in dataset";
      return os.str();
    }
  }
  return "";
}

std::string validateIfaceName(const std::string &name) {
  if (name.empty()) return "interface name is empty";
  if (name.size() > 15) return "interface name longer than 15 chars";
  for (char c : name) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in interface name";
      return os.str();
    }
  }
  return "";
}

std::string validateMacAddress(const std::string &mac) {
  if (mac.empty()) return ""; // empty = kernel-assigned
  // Accept aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff.
  if (mac.size() != 17) return "MAC must be 17 chars (aa:bb:cc:dd:ee:ff)";
  char sep = mac[2];
  if (sep != ':' && sep != '-') return "MAC separator must be ':' or '-'";
  for (size_t i = 0; i < 17; i++) {
    if (i % 3 == 2) {
      if (mac[i] != sep) return "inconsistent MAC separator";
    } else {
      if (!isHexDigit(mac[i])) return "MAC must be hex digits";
    }
  }
  // Reject multicast bit (low bit of first octet) as a foot-gun.
  // Operators rarely want a multicast MAC on a unicast iface.
  unsigned firstOctet = 0;
  for (int i = 0; i < 2; i++) {
    char c = mac[i];
    unsigned d = (c >= '0' && c <= '9') ? (unsigned)(c - '0')
                : (c >= 'a' && c <= 'f') ? (unsigned)(10 + c - 'a')
                : (unsigned)(10 + c - 'A');
    firstOctet = firstOctet * 16 + d;
  }
  if (firstOctet & 0x01) return "MAC multicast bit set in first octet";
  return "";
}

namespace {

// Tiny IPv4 octet check. Returns -1 on parse error, 0..255 otherwise.
int parseIpv4Octet(const std::string &s) {
  if (s.empty() || s.size() > 3) return -1;
  // Reject leading zeros for >1-digit numbers (octal-look-alikes).
  if (s.size() > 1 && s[0] == '0') return -1;
  unsigned long v = 0;
  if (!parseUnsignedDec(s, v)) return -1;
  if (v > 255) return -1;
  return (int)v;
}

} // anon

std::string validateIpv4Cidr(const std::string &cidr) {
  if (cidr.empty()) return "";
  auto slash = cidr.find('/');
  if (slash == std::string::npos) return "IPv4 CIDR missing '/' prefix length";
  std::string addr = cidr.substr(0, slash);
  std::string plen = cidr.substr(slash + 1);
  unsigned long pv = 0;
  if (!parseUnsignedDec(plen, pv) || pv > 32)
    return "IPv4 prefix length out of range (0..32)";
  // Split addr by '.', expect exactly 4 octets.
  std::vector<std::string> parts;
  std::string cur;
  for (char c : addr) {
    if (c == '.') { parts.push_back(cur); cur.clear(); }
    else cur.push_back(c);
  }
  parts.push_back(cur);
  if (parts.size() != 4) return "IPv4 address must have 4 octets";
  for (const auto &p : parts) {
    if (parseIpv4Octet(p) < 0) return "IPv4 octet out of range or malformed";
  }
  return "";
}

std::string validateIpv6Cidr(const std::string &cidr) {
  if (cidr.empty()) return "";
  auto slash = cidr.find('/');
  if (slash == std::string::npos) return "IPv6 CIDR missing '/' prefix length";
  std::string addr = cidr.substr(0, slash);
  std::string plen = cidr.substr(slash + 1);
  unsigned long pv = 0;
  if (!parseUnsignedDec(plen, pv) || pv > 128)
    return "IPv6 prefix length out of range (0..128)";
  if (addr.empty()) return "IPv6 address is empty";
  if (addr.size() > 45) return "IPv6 address longer than 45 chars";
  // Allow exactly one '::' compression sequence; otherwise require
  // colon-separated hex groups.
  size_t doubleColon = addr.find("::");
  if (doubleColon != std::string::npos
      && addr.find("::", doubleColon + 1) != std::string::npos)
    return "IPv6 address has more than one '::'";
  // Charset check + group-length check.
  std::string cur;
  int groups = 0;
  bool sawDoubleColon = false;
  for (size_t i = 0; i < addr.size(); i++) {
    char c = addr[i];
    if (c == ':') {
      if (i + 1 < addr.size() && addr[i + 1] == ':') {
        if (sawDoubleColon) return "IPv6 address has more than one '::'";
        sawDoubleColon = true;
        if (!cur.empty()) {
          if (cur.size() > 4) return "IPv6 group longer than 4 hex digits";
          groups++;
          cur.clear();
        }
        i++; // skip second ':'
        continue;
      }
      if (cur.empty()) return "empty IPv6 group";
      if (cur.size() > 4) return "IPv6 group longer than 4 hex digits";
      groups++;
      cur.clear();
    } else {
      if (!isHexDigit(c)) {
        std::ostringstream os;
        os << "invalid character '" << c << "' in IPv6 address";
        return os.str();
      }
      cur.push_back(c);
    }
  }
  if (!cur.empty()) {
    if (cur.size() > 4) return "IPv6 group longer than 4 hex digits";
    groups++;
  }
  if (sawDoubleColon) {
    if (groups > 7) return "IPv6 has too many groups around '::'";
  } else {
    if (groups != 8) return "IPv6 must have 8 groups when '::' is absent";
  }
  return "";
}

std::string validateRuleText(const std::string &text) {
  if (text.empty()) return "rule text is empty";
  if (text.size() > 1024) return "rule text longer than 1024 chars";
  // No newlines — rules are exactly one line. Backtick + dollar
  // are rejected even though pf/ipfw don't expand them, because
  // the caller may unfortunate-pipe these into an exec wrapper.
  for (char c : text) {
    if (c == '\n' || c == '\r') return "rule text must be a single line";
    if (c == '`' || c == '$' || c == ';' || c == '\\')
      return "rule text contains shell metacharacters";
  }
  return "";
}

std::string validateAnchorName(const std::string &name) {
  if (name.empty()) return "anchor name is empty";
  if (name.size() > 64) return "anchor name longer than 64 chars";
  for (char c : name) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in anchor name";
      return os.str();
    }
  }
  return "";
}

std::string validateIpfwAction(const std::string &action) {
  if (action == "allow") return "";
  if (action == "deny") return "";
  if (action == "skipto") return "";
  if (action == "nat") return "";
  if (action == "fwd") return "";
  if (action == "count") return "";
  if (action == "check-state") return "";
  if (action == "reset") return "";
  return "unknown ipfw action";
}

// --- Per-verb validators ---

std::string validateCreateJail(const CreateJailReq &r) {
  if (auto e = validateJailName(r.name); !e.empty()) return e;
  if (auto e = validateAbsolutePath(r.path); !e.empty()) return e;
  if (auto e = validateHostname(r.hostname); !e.empty()) return e;
  // `parameters` is the optional jail.conf fragment. Allow empty;
  // reject newlines/shell-metas if present so the daemon can pass
  // it to jail -m without surprises. (Operators with complex
  // jail.conf needs use a config file, not this field.)
  if (!r.parameters.empty()) {
    if (r.parameters.size() > 4096) return "jail parameters longer than 4096 chars";
    if (auto e = validateRuleText(r.parameters); !e.empty()) return "jail parameters: " + e;
  }
  return "";
}

std::string validateDestroyJail(const DestroyJailReq &r) {
  if (auto e = validateJailName(r.name); !e.empty()) return e;
  return "";
}

std::string validateMountNullfs(const MountNullfsReq &r) {
  if (auto e = validateAbsolutePath(r.source); !e.empty()) return "source: " + e;
  if (auto e = validateAbsolutePath(r.target); !e.empty()) return "target: " + e;
  return "";
}

std::string validateUnmountNullfs(const UnmountNullfsReq &r) {
  if (auto e = validateAbsolutePath(r.target); !e.empty()) return "target: " + e;
  return "";
}

std::string validateSetRctl(const SetRctlReq &r) {
  if (r.jid < 1) return "jid must be >= 1";
  if (auto e = RetunePure::validateRctlKey(r.key); !e.empty()) return e;
  if (auto e = RetunePure::validateRctlValue(r.key, r.rawValue); !e.empty()) return e;
  return "";
}

std::string validateClearRctl(const ClearRctlReq &r) {
  if (r.jid < 1) return "jid must be >= 1";
  if (auto e = RetunePure::validateRctlKey(r.key); !e.empty()) return e;
  return "";
}

std::string validateAttachZfs(const AttachZfsReq &r) {
  if (r.jid < 1) return "jid must be >= 1";
  if (auto e = validateZfsDataset(r.dataset); !e.empty()) return e;
  return "";
}

std::string validateDetachZfs(const DetachZfsReq &r) {
  if (r.jid < 1) return "jid must be >= 1";
  if (auto e = validateZfsDataset(r.dataset); !e.empty()) return e;
  return "";
}

std::string validateConfigureIface(const ConfigureIfaceReq &r) {
  if (r.jid < 1) return "jid must be >= 1";
  if (auto e = validateIfaceName(r.ifname); !e.empty()) return "ifname: " + e;
  if (!r.bridge.empty()) {
    if (auto e = validateIfaceName(r.bridge); !e.empty()) return "bridge: " + e;
  }
  if (auto e = validateIpv4Cidr(r.ipv4Cidr); !e.empty()) return "ipv4: " + e;
  if (auto e = validateIpv6Cidr(r.ipv6Cidr); !e.empty()) return "ipv6: " + e;
  if (auto e = validateMacAddress(r.macAddr); !e.empty()) return "mac: " + e;
  if (r.ipv4Cidr.empty() && r.ipv6Cidr.empty())
    return "at least one of ipv4 or ipv6 CIDR must be set";
  return "";
}

std::string validateTeardownIface(const TeardownIfaceReq &r) {
  if (auto e = validateIfaceName(r.ifname); !e.empty()) return e;
  return "";
}

std::string validateAddPfRule(const AddPfRuleReq &r) {
  if (auto e = validateAnchorName(r.anchor); !e.empty()) return "anchor: " + e;
  if (auto e = validateRuleText(r.ruleText); !e.empty()) return "rule: " + e;
  return "";
}

std::string validateRemovePfRule(const RemovePfRuleReq &r) {
  if (auto e = validateAnchorName(r.anchor); !e.empty()) return "anchor: " + e;
  if (auto e = validateRuleText(r.ruleText); !e.empty()) return "rule: " + e;
  return "";
}

std::string validateAddIpfwRule(const AddIpfwRuleReq &r) {
  if (r.set > 31) return "ipfw set out of range (0..31)";
  if (r.number < 1 || r.number > 65534) return "ipfw rule number out of range (1..65534)";
  if (auto e = validateIpfwAction(r.action); !e.empty()) return e;
  if (auto e = validateRuleText(r.body); !e.empty()) return "body: " + e;
  return "";
}

std::string validateRemoveIpfwRule(const RemoveIpfwRuleReq &r) {
  if (r.set > 31) return "ipfw set out of range (0..31)";
  if (r.number < 1 || r.number > 65534) return "ipfw rule number out of range (1..65534)";
  return "";
}

std::string validateSetIfaceUp(const SetIfaceUpReq &r) {
  return validateIfaceName(r.ifname);
}

std::string validateDisableIfaceOffload(const DisableIfaceOffloadReq &r) {
  return validateIfaceName(r.ifname);
}

std::string validateBridgeAddMember(const BridgeAddMemberReq &r) {
  if (auto e = validateIfaceName(r.bridge); !e.empty()) return "bridge: " + e;
  if (auto e = validateIfaceName(r.member); !e.empty()) return "member: " + e;
  return "";
}

std::string validateBridgeDelMember(const BridgeDelMemberReq &r) {
  if (auto e = validateIfaceName(r.bridge); !e.empty()) return "bridge: " + e;
  if (auto e = validateIfaceName(r.member); !e.empty()) return "member: " + e;
  return "";
}

std::string validateSetIfaceInetAddr(const SetIfaceInetAddrReq &r) {
  if (auto e = validateIfaceName(r.ifname); !e.empty()) return "ifname: " + e;
  if (r.prefixLen > 32) return "prefix_len out of range (0..32)";
  // Reuse validateIpv4Cidr by reassembling addr+prefix; cheaper than
  // duplicating the IPv4 octet logic.
  std::string cidr = r.addr + "/" + std::to_string(r.prefixLen);
  if (auto e = validateIpv4Cidr(cidr); !e.empty()) return "addr: " + e;
  return "";
}

std::string validateCreateEpair(const CreateEpairReq &) {
  // No fields — kernel picks the unit number. Validator is here
  // for symmetry with the rest of the verb set; always succeeds.
  return "";
}

std::string validateSetLoginclassRctl(const SetLoginclassRctlReq &r) {
  if (auto e = PerUserRctlPure::validateLoginclassName(r.loginclass); !e.empty())
    return "loginclass: " + e;
  if (auto e = RetunePure::validateRctlKey(r.key); !e.empty()) return e;
  if (auto e = RetunePure::validateRctlValue(r.key, r.rawValue); !e.empty()) return e;
  return "";
}

std::string validateClearLoginclassRctl(const ClearLoginclassRctlReq &r) {
  if (auto e = PerUserRctlPure::validateLoginclassName(r.loginclass); !e.empty())
    return "loginclass: " + e;
  if (auto e = RetunePure::validateRctlKey(r.key); !e.empty()) return e;
  return "";
}

std::string validateReclaimIfaceFromVnet(const ReclaimIfaceFromVnetReq &r) {
  if (auto e = validateIfaceName(r.ifname);   !e.empty()) return "ifname: " + e;
  if (auto e = validateJailName(r.jailName);  !e.empty()) return "jail_name: " + e;
  return "";
}

} // namespace PrivOpsPure
