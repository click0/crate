// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ipsec_pure.h"

#include <sstream>

namespace IpsecPure {

// We share the lightweight IP/hostname validators with the WireGuard
// module's local copies (kept independent so this header pulls in no
// other module). The implementations are identical in spirit; we
// duplicate the small ones here for clarity.

namespace {

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

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
  size_t i = 0;
  int groups = 0;
  while (i < s.size()) {
    if (i + 1 < s.size() && s[i] == ':' && s[i + 1] == ':') {
      if (sawDoubleColon) return false;
      sawDoubleColon = true;
      i += 2;
      continue;
    }
    if (s[i] == ':') {
      if (groups == 0) return false;
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
    groups++;
  }
  if (sawDoubleColon) return groups <= 7;
  return groups == 8;
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

} // anon

// True iff `s` is a dotted-numeric string ([0-9.]+). Such strings
// must validate as IPv4 — they are never legal hostnames per RFC
// 1123 (a label can't be all digits) and we want a clear error if
// an octet is out of range rather than silently accepting it.
static bool looksLikeV4Shape(const std::string &s) {
  if (s.empty()) return false;
  bool sawDot = false;
  for (char c : s) {
    if (c == '.') { sawDot = true; continue; }
    if (c < '0' || c > '9') return false;
  }
  return sawDot;
}

std::string validateHost(const std::string &host) {
  if (host.empty())     return "host is empty";
  if (host == "%any")   return "";  // strongSwan wildcard, common for road-warriors
  // Bracketed IPv6 (rare in `left=`, but accepted).
  if (host.front() == '[' && host.back() == ']') {
    auto inner = host.substr(1, host.size() - 2);
    if (!isV6(inner)) return "host IPv6 literal is malformed";
    return "";
  }
  // If it looks like IPv4 (dotted-numeric), it must validate as IPv4 —
  // otherwise out-of-range octets like 256.0.0.1 silently fall through
  // to hostname validation.
  if (looksLikeV4Shape(host)) {
    if (isV4(host)) return "";
    return "host looks like IPv4 but has invalid octets";
  }
  if (isV6(host) || isHostname(host)) return "";
  return "host is neither a valid IPv4, IPv6, nor hostname";
}

std::string validateSubnet(const std::string &subnet) {
  if (subnet.empty()) return "subnet is empty";
  auto slash = subnet.find('/');
  if (slash == std::string::npos)
    return "subnet must include a '/<prefix>' suffix";
  auto host   = subnet.substr(0, slash);
  auto prefix = subnet.substr(slash + 1);
  if (host.empty())   return "subnet host part is empty";
  if (prefix.empty()) return "subnet prefix is empty";
  for (char c : prefix)
    if (c < '0' || c > '9') return "subnet prefix must be numeric";
  long p = 0;
  for (char c : prefix) p = p * 10 + (c - '0');
  bool v4 = isV4(host);
  bool v6 = !v4 && isV6(host);
  if (!v4 && !v6) return "subnet host is neither IPv4 nor IPv6";
  long max = v4 ? 32 : 128;
  if (p < 0 || p > max)
    return v4 ? "IPv4 subnet prefix must be 0..32"
              : "IPv6 subnet prefix must be 0..128";
  return "";
}

std::string validateProposal(const std::string &p) {
  if (p.empty()) return "proposal is empty";
  if (p.size() > 128) return "proposal is longer than 128 chars";
  for (char c : p) {
    bool ok = isAlnum(c) || c == '-' || c == '_';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in proposal";
      return os.str();
    }
  }
  return "";
}

std::string validateAuto(const std::string &v) {
  if (v == "ignore" || v == "add" || v == "route" || v == "start") return "";
  return "auto must be one of: ignore | add | route | start";
}

std::string validateAuthby(const std::string &v) {
  if (v == "psk" || v == "pubkey" || v == "rsasig"
      || v == "ecdsasig" || v == "never") return "";
  return "authby must be one of: psk | pubkey | rsasig | ecdsasig | never";
}

std::string validateConnName(const std::string &name) {
  if (name.empty()) return "conn name is empty";
  if (name.size() > 32) return "conn name is longer than 32 chars";
  if (name == "%default") return "conn name '%default' is reserved";
  for (char c : name) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in conn name";
      return os.str();
    }
  }
  return "";
}

namespace {

std::string prefixed(size_t i, const std::string &msg) {
  return "conn #" + std::to_string(i + 1) + ": " + msg;
}

} // anon

std::string validateConfig(const std::vector<ConnSpec> &conns) {
  if (conns.empty()) return "config must contain at least one conn";
  for (size_t i = 0; i < conns.size(); i++) {
    auto &c = conns[i];
    if (auto e = validateConnName(c.name); !e.empty())
      return prefixed(i, e);
    if (auto e = validateHost(c.left); !e.empty())
      return prefixed(i, "left: " + e);
    if (auto e = validateHost(c.right); !e.empty())
      return prefixed(i, "right: " + e);
    for (auto &s : c.leftSubnet)
      if (auto e = validateSubnet(s); !e.empty())
        return prefixed(i, "leftsubnet '" + s + "': " + e);
    for (auto &s : c.rightSubnet)
      if (auto e = validateSubnet(s); !e.empty())
        return prefixed(i, "rightsubnet '" + s + "': " + e);
    if (!c.ike.empty())
      if (auto e = validateProposal(c.ike); !e.empty())
        return prefixed(i, "ike: " + e);
    if (!c.esp.empty())
      if (auto e = validateProposal(c.esp); !e.empty())
        return prefixed(i, "esp: " + e);
    if (!c.keyExchange.empty()) {
      if (c.keyExchange != "ike" && c.keyExchange != "ikev1"
          && c.keyExchange != "ikev2")
        return prefixed(i, "keyexchange must be ike | ikev1 | ikev2");
    }
    if (!c.authBy.empty())
      if (auto e = validateAuthby(c.authBy); !e.empty())
        return prefixed(i, e);
    if (!c.autoStart.empty())
      if (auto e = validateAuto(c.autoStart); !e.empty())
        return prefixed(i, e);
  }
  return "";
}

namespace {

void emitCsvList(std::ostringstream &os, const char *key,
                 const std::vector<std::string> &v) {
  if (v.empty()) return;
  os << "    " << key << "=";
  for (size_t i = 0; i < v.size(); i++) {
    if (i) os << ",";
    os << v[i];
  }
  os << "\n";
}

void emitOptional(std::ostringstream &os, const char *key,
                  const std::string &val) {
  if (!val.empty()) os << "    " << key << "=" << val << "\n";
}

} // anon

std::string renderConf(const std::vector<ConnSpec> &conns) {
  std::ostringstream os;
  os << "# Generated by crate(8) — strongSwan ipsec.conf compatible.\n"
     << "# Apply with: ipsec reload && ipsec up <conn-name>\n\n"
     << "config setup\n"
     << "    charondebug=\"ike 2, knl 2, cfg 2\"\n";

  for (auto &c : conns) {
    os << "\n";
    if (!c.description.empty())
      os << "# " << c.description << "\n";
    os << "conn " << c.name << "\n";
    emitOptional(os, "left",      c.left);
    emitOptional(os, "leftid",    c.leftId);
    emitCsvList (os, "leftsubnet", c.leftSubnet);
    emitOptional(os, "right",     c.right);
    emitOptional(os, "rightid",   c.rightId);
    emitCsvList (os, "rightsubnet", c.rightSubnet);
    emitOptional(os, "keyexchange", c.keyExchange);
    emitOptional(os, "ike",       c.ike);
    emitOptional(os, "esp",       c.esp);
    emitOptional(os, "authby",    c.authBy);
    emitOptional(os, "auto",      c.autoStart);
  }
  return os.str();
}

} // namespace IpsecPure
