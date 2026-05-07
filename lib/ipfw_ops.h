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
//
// 0.8.37 status: scaffolding, no production caller. crate's
// per-jail rule numbers (40000+jid for auto-fw, 20000+jid*2
// for throttle pairs) are not currently grouped into ipfw
// "sets" — they're individual numbered rules. To wire this
// helper, the auto-fw runtime needs to be refactored to
// `add SET <set> <num> ...` per jail, after which a single
// `deleteRulesInSet` would replace the per-id `deleteRule`
// loop in `crate clean` (lib/clean.cpp section 5). Tracked
// as a future architectural change.
void deleteRulesInSet(unsigned setNum);

// NAT configuration
void configureNat(unsigned natInstance, const std::string &natConfig);
void deleteNat(unsigned natInstance);

}
