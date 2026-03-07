// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// PF firewall operations using libpfctl (FreeBSD 14+) with pfctl(8) fallback.

#pragma once

#include <string>
#include <vector>

namespace PfctlOps {

bool available();

// Manage PF anchors for crate containers.
// Each jail gets its own anchor: crate/<jailname>
void addRules(const std::string &anchor, const std::vector<std::string> &rules);
void flushRules(const std::string &anchor);

// NAT / RDR rules
void addNatRule(const std::string &anchor,
                const std::string &srcNet, const std::string &natAddr);
void addRdrRule(const std::string &anchor,
                const std::string &extAddr, int extPort,
                const std::string &intAddr, int intPort,
                const std::string &proto = "tcp");

}
