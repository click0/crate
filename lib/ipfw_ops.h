// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// IPFW firewall operations via raw socket + IP_FW3 with ipfw(8) fallback.

#pragma once

#include <string>
#include <vector>

namespace IpfwOps {

bool available();

// Runtime detection: returns true if the native IP_FW3 setsockopt API
// is functional on this system.  Result is probed once and cached.
bool useNativeApi();

// Enable/disable performance timing output for native vs shell operations.
void setLogProgress(bool enabled);

// Add a firewall rule. ruleNum=0 for auto-numbering.
void addRule(unsigned ruleNum, const std::string &rule);

// Delete a rule by number.
void deleteRule(unsigned ruleNum);

// Delete all rules matching a table/set.
void deleteRulesInSet(unsigned setNum);

// NAT configuration
void configureNat(unsigned natInstance, const std::string &natConfig);
void deleteNat(unsigned natInstance);

// Common patterns used by crate
void addNatForJail(unsigned ruleNum, unsigned natInstance,
                   const std::string &jailIp, const std::string &extIface);
void addPortForward(unsigned ruleNum, unsigned natInstance,
                    const std::string &extIp, int extPort,
                    const std::string &jailIp, int jailPort,
                    const std::string &proto = "tcp");

}
