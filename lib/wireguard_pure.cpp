// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "wireguard_pure.h"

#include <sstream>

namespace WireguardPure {

namespace {

bool isBase64Char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
      || (c >= '0' && c <= '9') || c == '+' || c == '/';
}

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

bool isV4Octet(const std::string &s) {
  if (s.empty() || s.size() > 3) return false;
  for (char c : s) if (c < '0' || c > '9') return false;
  int n = 0;
  for (char c : s) n = n * 10 + (c - '0');
  return n >= 0 && n <= 255;
}

// Lightweight IPv4 validation: four dot-separated octets, each ≤ 255.
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

// Lightweight IPv6 validation: hex groups separated by ':', allows
// one '::' shorthand. Doesn't validate embedded IPv4 (rare).
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
    // Hex group: 1..4 hex digits.
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
  if (sawDoubleColon)  return groups <= 7;
  return groups == 8;
}

bool isHostname(const std::string &s) {
  if (s.empty() || s.size() > 253) return false;
  // Each label ≤63, alnum bookends, body adds '-'. Labels
  // separated by '.'.
  size_t i = 0;
  while (i < s.size()) {
    size_t labelStart = i;
    while (i < s.size() && s[i] != '.') i++;
    auto label = s.substr(labelStart, i - labelStart);
    if (label.empty() || label.size() > 63) return false;
    if (!isAlnum(label.front()) || !isAlnum(label.back())) return false;
    for (char c : label)
      if (!isAlnum(c) && c != '-') return false;
    if (i < s.size()) i++; // skip dot
  }
  return true;
}

} // anon

std::string validateKey(const std::string &keyB64) {
  if (keyB64.size() != 44)
    return "WireGuard key must be exactly 44 base64 characters (32 raw bytes)";
  if (keyB64.back() != '=')
    return "WireGuard key must end with '=' padding";
  for (size_t i = 0; i < 43; i++) {
    if (!isBase64Char(keyB64[i]))
      return "WireGuard key contains a non-base64 character";
  }
  // For 32-byte input, the 43rd char's low 4 bits must be zero
  // (because 32*8 mod 6 = 4 → padding bits are at the end). Skip
  // this strictness — wg(8) doesn't enforce it either, and operators
  // sometimes paste keys with cosmetic whitespace already stripped.
  return "";
}

std::string validatePort(const std::string &port) {
  if (port.empty()) return "ListenPort is empty";
  for (char c : port)
    if (c < '0' || c > '9') return "ListenPort must be numeric";
  long n = 0;
  for (char c : port) {
    n = n * 10 + (c - '0');
    if (n > 65535) return "ListenPort out of range (1..65535)";
  }
  if (n < 1) return "ListenPort out of range (1..65535)";
  return "";
}

std::string validateCidr(const std::string &cidr) {
  if (cidr.empty()) return "CIDR is empty";
  auto slash = cidr.find('/');
  if (slash == std::string::npos)
    return "CIDR must include a '/<prefix>' suffix";
  auto host   = cidr.substr(0, slash);
  auto prefix = cidr.substr(slash + 1);
  if (host.empty()) return "CIDR host part is empty";
  if (prefix.empty()) return "CIDR prefix is empty";
  for (char c : prefix)
    if (c < '0' || c > '9') return "CIDR prefix must be numeric";
  long p = 0;
  for (char c : prefix) p = p * 10 + (c - '0');
  bool v4 = isV4(host);
  bool v6 = !v4 && isV6(host);
  if (!v4 && !v6) return "CIDR host part is neither valid IPv4 nor IPv6";
  long max = v4 ? 32 : 128;
  if (p < 0 || p > max)
    return v4 ? "IPv4 CIDR prefix must be 0..32" : "IPv6 CIDR prefix must be 0..128";
  return "";
}

std::string validateEndpoint(const std::string &endpoint) {
  if (endpoint.empty()) return "endpoint is empty";
  // IPv6 literal: [::1]:51820
  if (endpoint.front() == '[') {
    auto rb = endpoint.find(']');
    if (rb == std::string::npos) return "endpoint missing closing ']'";
    auto host = endpoint.substr(1, rb - 1);
    if (rb + 1 >= endpoint.size() || endpoint[rb + 1] != ':')
      return "endpoint missing ':' after ']'";
    auto port = endpoint.substr(rb + 2);
    if (!isV6(host)) return "endpoint IPv6 literal is malformed";
    return validatePort(port);
  }
  // host:port (IPv4 or hostname)
  auto colon = endpoint.rfind(':');
  if (colon == std::string::npos) return "endpoint must be host:port";
  auto host = endpoint.substr(0, colon);
  auto port = endpoint.substr(colon + 1);
  if (!isV4(host) && !isHostname(host))
    return "endpoint host is neither IPv4 nor a valid hostname";
  return validatePort(port);
}

std::string validateConfig(const InterfaceSpec &iface,
                           const std::vector<PeerSpec> &peers) {
  // Interface
  if (auto e = validateKey(iface.privateKey); !e.empty())
    return "interface PrivateKey: " + e;
  if (iface.addresses.empty())
    return "interface must have at least one Address";
  for (auto &a : iface.addresses)
    if (auto e = validateCidr(a); !e.empty())
      return "interface Address '" + a + "': " + e;
  if (!iface.listenPort.empty())
    if (auto e = validatePort(iface.listenPort); !e.empty())
      return "interface ListenPort: " + e;

  // Peers
  if (peers.empty())
    return "config must have at least one [Peer] section";
  for (size_t i = 0; i < peers.size(); i++) {
    auto &p = peers[i];
    if (auto e = validateKey(p.publicKey); !e.empty())
      return "peer #" + std::to_string(i + 1) + " PublicKey: " + e;
    if (!p.presharedKey.empty())
      if (auto e = validateKey(p.presharedKey); !e.empty())
        return "peer #" + std::to_string(i + 1) + " PresharedKey: " + e;
    if (p.allowedIps.empty())
      return "peer #" + std::to_string(i + 1) + " must have at least one AllowedIPs entry";
    for (auto &a : p.allowedIps)
      if (auto e = validateCidr(a); !e.empty())
        return "peer #" + std::to_string(i + 1) + " AllowedIPs '" + a + "': " + e;
    if (!p.endpoint.empty())
      if (auto e = validateEndpoint(p.endpoint); !e.empty())
        return "peer #" + std::to_string(i + 1) + " Endpoint: " + e;
    if (!p.persistentKeepalive.empty()) {
      for (char c : p.persistentKeepalive)
        if (c < '0' || c > '9')
          return "peer #" + std::to_string(i + 1) + " PersistentKeepalive must be numeric";
    }
  }
  return "";
}

namespace {

void emitCsvList(std::ostringstream &os, const char *key,
                 const std::vector<std::string> &v) {
  if (v.empty()) return;
  os << key << " = ";
  for (size_t i = 0; i < v.size(); i++) {
    if (i) os << ", ";
    os << v[i];
  }
  os << "\n";
}

} // anon

std::string renderConf(const InterfaceSpec &iface,
                       const std::vector<PeerSpec> &peers) {
  std::ostringstream os;
  os << "# Generated by crate(8) — wg-quick(8) compatible.\n"
     << "# Apply with: wg-quick up <this-file>\n\n";
  os << "[Interface]\n";
  os << "PrivateKey = " << iface.privateKey << "\n";
  emitCsvList(os, "Address", iface.addresses);
  if (!iface.listenPort.empty())
    os << "ListenPort = " << iface.listenPort << "\n";
  if (!iface.fwmark.empty())
    os << "FwMark = "    << iface.fwmark << "\n";
  emitCsvList(os, "DNS", iface.dns);
  if (!iface.mtu.empty() && !iface.mtu.front().empty())
    os << "MTU = " << iface.mtu.front() << "\n";

  for (auto &p : peers) {
    os << "\n";
    if (!p.description.empty())
      os << "# " << p.description << "\n";
    os << "[Peer]\n";
    os << "PublicKey = " << p.publicKey << "\n";
    if (!p.presharedKey.empty())
      os << "PresharedKey = " << p.presharedKey << "\n";
    emitCsvList(os, "AllowedIPs", p.allowedIps);
    if (!p.endpoint.empty())
      os << "Endpoint = " << p.endpoint << "\n";
    if (!p.persistentKeepalive.empty())
      os << "PersistentKeepalive = " << p.persistentKeepalive << "\n";
  }
  return os.str();
}

} // namespace WireguardPure
