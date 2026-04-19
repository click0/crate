// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// PF firewall operations using libpfctl (FreeBSD 14+) with pfctl(8) fallback.

#pragma once

#include "spec.h"

#include <string>
#include <vector>

namespace PfctlOps {

bool available();

// Manage PF anchors for crate containers.
// Each jail gets its own anchor: crate/<jailname>
void addRules(const std::string &anchor, const std::vector<std::string> &rules);
void addRules(const std::string &anchor, const std::string &rulesText);
void flushRules(const std::string &anchor);

// Build pf rules from a container's FirewallPolicy and load them into
// the anchor crate/<jailXname>.  ipv4 is the jail-side IPv4 address;
// ipv6 is the jail-side IPv6 address (empty string to skip IPv6 rules).
// Returns the anchor name so the caller can set up cleanup.
std::string loadContainerPolicy(const Spec &spec,
                                const std::string &jailXname,
                                const std::string &ipv4,
                                const std::string &ipv6);

}
