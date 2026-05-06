// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for auto-firewall rule generation (0.8.0).
//
// When `mode: auto` (0.7.18) allocates an IP from the network pool
// (0.7.17), the jail also needs an SNAT rule to actually reach the
// outside world — without that, a packet leaves the jail with a
// 10.66.0.x source address that never gets translated, and replies
// can't be routed back. Pre-0.8.0 operators wrote pf.conf entries
// by hand:
//
//   nat on em0 inet from 10.66.0.0/24 to ! 10.66.0.0/24 -> (em0)
//
// This module formats those rules per-jail (one rule per allocated
// IP) for loading into the existing per-jail pf anchor
// `crate/<jailname>`. PfctlOps::addRules + flushRules already
// cover the lifecycle.
//
// Pure: no shell-out, no system probing. Detection of the external
// interface and pf-vs-ipfw is in lib/auto_fw.cpp.
//

#include <string>

namespace AutoFwPure {

// Validate the external interface name a jail's SNAT rule will pin
// to (host-side). Same rules as Util::validIfaceName but inlined
// here so this module stays standalone:
//   - 1..15 chars (FreeBSD IFNAMSIZ minus terminator)
//   - alnum + '.' (for vlan0.100) + '_'
//   - no shell metacharacters, no whitespace
// Returns "" on success.
std::string validateExternalIface(const std::string &iface);

// Validate a jail-side IPv4 address as it appears in an SNAT rule.
// We accept dotted-quad with optional `/<prefix>` suffix because
// pf rules accept both "10.66.0.5" and "10.66.0.0/24".
//   - 1..18 chars
//   - digits + dots + optional slash + digits
// Detailed CIDR validation is in IpAllocPure; here we just gate
// against shell injection / weird input.
std::string validateRuleAddress(const std::string &addr);

// Format the SNAT rule for one jail. Output:
//
//   nat on <externalIface> inet from <jailAddr> to ! <jailAddr> -> (<externalIface>)
//
// The "to !<jailAddr>" exclusion prevents NAT'ing intra-jail
// traffic — replies between two jails on the same bridge stay on
// the bridge instead of being source-NAT'd to the host's address.
//
// Caller is responsible for invoking the validators above first.
// The format helper itself does no validation (purely string-
// formatting) so a typo in the validator surfaces in tests rather
// than as a malformed pf rule at runtime.
std::string formatSnatRule(const std::string &externalIface,
                           const std::string &jailAddr);

// Format a single per-jail SNAT line so it can be injected into
// the pf anchor crate/<jailname>. Trailing newline included so
// multiple lines concat cleanly.
std::string formatSnatAnchorLine(const std::string &externalIface,
                                 const std::string &jailAddr);

} // namespace AutoFwPure
