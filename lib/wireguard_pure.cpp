// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "wireguard_pure.h"
#include "netaddr_pure.h"

#include <sstream>

namespace WireguardPure {

namespace {

// 1.1.30: shared, verified-identical predicates (lib/netaddr_pure.h).
using NetAddrPure::isV4;
using NetAddrPure::isV6;
using NetAddrPure::isHostname;

bool isBase64Char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
      || (c >= '0' && c <= '9') || c == '+' || c == '/';
}

// 1.1.21: a free-text field (DNS, FwMark, MTU, peer description) is
// emitted verbatim into the wg-quick .conf. A newline would let it
// inject its own directives — most dangerously `PostUp = <cmd>`, which
// wg-quick runs as root. Reject any control byte (incl. \n/\r) and DEL.
bool hasControlChar(const std::string &s) {
  for (char c : s)
    if (static_cast<unsigned char>(c) < 0x20 ||
        static_cast<unsigned char>(c) == 0x7f)
      return true;
  return false;
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
  // 1.1.21: fields emitted verbatim into the .conf must not carry a
  // newline/control byte (would inject wg-quick directives like PostUp,
  // which runs as root). validateConfig previously skipped these.
  if (hasControlChar(iface.fwmark))
    return "interface FwMark contains a control character";
  for (auto &d : iface.dns)
    if (hasControlChar(d))
      return "interface DNS entry '" + d + "' contains a control character";
  if (!iface.mtu.empty() && hasControlChar(iface.mtu.front()))
    return "interface MTU contains a control character";

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
    // 1.1.21: the peer description is rendered as a `# <description>`
    // comment line — a newline escapes the comment and injects a
    // directive into the [Interface]/[Peer] scope.
    if (hasControlChar(p.description))
      return "peer #" + std::to_string(i + 1) +
             " description contains a control character";
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
