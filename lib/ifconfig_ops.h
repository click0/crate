// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Network interface operations using libifconfig with fallback to ifconfig(8).
// Compile with HAVE_LIBIFCONFIG defined and link -lifconfig for native API.

#pragma once

#include <string>
#include <utility>

namespace IfconfigOps {

// Whether native libifconfig API is available (compile-time check).
bool available();

// Create an epair interface pair. Returns (epairNa, epairNb) names.
std::pair<std::string, std::string> createEpair();

// Destroy an interface.
void destroyInterface(const std::string &name);

// Set IPv4 address with prefix length (e.g. "10.0.0.1", 30).
void setInetAddr(const std::string &iface, const std::string &addr, int prefixLen);

// Set IPv6 address with prefix length.
void setInet6Addr(const std::string &iface, const std::string &addr, int prefixLen);

// Move interface into a VNET jail.
void moveToVnet(const std::string &iface, int jid);

// Disable TCP checksum offloading (txcsum, txcsum6, rxcsum, rxcsum6).
void disableOffload(const std::string &iface);

// Disable LRO/TSO (performance fix for VNET jails on FreeBSD 14+).
void disableLroTso(const std::string &iface);

// Add a member interface to a bridge.
void bridgeAddMember(const std::string &bridge, const std::string &member);

// Remove a member interface from a bridge.
void bridgeDelMember(const std::string &bridge, const std::string &member);

// Set interface UP.
void setUp(const std::string &iface);

// Set interface DOWN.
void setDown(const std::string &iface);

// Set MAC address (6 bytes).
void setMacAddr(const std::string &iface, const unsigned char mac[6]);

// Set MAC address from string (e.g. "58:9c:fc:ab:cd:ef").
void setMacAddr(const std::string &iface, const std::string &mac);

// Set interface description.
void setDescription(const std::string &iface, const std::string &desc);

// Create a VLAN interface.
std::string createVlan(const std::string &parentIface, int vlanId);

}
