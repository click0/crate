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
#include <vector>

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

// --- Port-forward (rdr) rules (0.8.1) ---

// Validate the proto field for an rdr rule. Returns "" on success,
// human-readable error otherwise. Accepted: "tcp", "udp".
std::string validateProto(const std::string &proto);

// Validate a port number for an rdr rule (1..65535). Returns "" on
// success.
std::string validatePort(unsigned port);

// Format a single rdr rule. The host-side and jail-side ports can
// be either single ports (a == b) or ranges (a < b). Output:
//
//   rdr on em0 inet proto tcp from any to (em0) port 8080 -> 10.66.0.5 port 80
//   rdr on em0 inet proto tcp from any to (em0) port 8080:8090 -> 10.66.0.5 port 80:90
//
// Range/single decision is per-side: the spec parser produces
// `pair<unsigned,unsigned>` host + jail tuples where first==second
// for a single port and first<second for a range. We mirror that
// in the rule output by switching to "X:Y" syntax only when needed.
//
// Caller is responsible for invoking the validators above first.
std::string formatRdrRule(const std::string &externalIface,
                          const std::string &proto,
                          unsigned hostPortLo, unsigned hostPortHi,
                          const std::string &jailAddr,
                          unsigned jailPortLo, unsigned jailPortHi);

// Same with trailing newline for clean line concatenation.
std::string formatRdrAnchorLine(const std::string &externalIface,
                                const std::string &proto,
                                unsigned hostPortLo, unsigned hostPortHi,
                                const std::string &jailAddr,
                                unsigned jailPortLo, unsigned jailPortHi);

// --- ipfw alternative backend (0.8.2) ---
//
// Operators using ipfw instead of pf get the same auto-fw via
// `ipfw nat` instances. Each jail gets its own NAT instance id
// (derived from JID) and one rule that activates it.
//
// Conventions:
//   natIdFor(jid) = 30000 + jid
//   ruleIdFor(jid) = 40000 + jid
//   (high numbers leave the low ranges for operator-defined rules.)
//
// We use SHELL ARGV form here (matching how `lib/throttle_pure.cpp`
// builds ipfw invocations) — much simpler than parsing an
// ipfw.conf chunk like pf needs.

unsigned natIdForJail(int jid);
unsigned ruleIdForJail(int jid);

// Validate the NAT instance id range. Returns "" on success.
// Caller passes the result of natIdForJail; this is a sanity belt.
std::string validateIpfwNatId(unsigned id);

// Build argv for `ipfw nat <id> config if <iface>` — installs the
// NAT instance for outbound translation. No port redirects in this
// release (port-forward via ipfw is deferred to 0.8.3).
std::vector<std::string> buildIpfwNatConfigArgv(unsigned natId,
                                                const std::string &externalIface);

// Build argv for the rule that activates the NAT for the jail's
// outbound traffic:
//   ipfw add <ruleId> nat <natId> ip from <jailAddr> to any out via <iface>
std::vector<std::string> buildIpfwNatRuleArgv(unsigned ruleId,
                                              unsigned natId,
                                              const std::string &jailAddr,
                                              const std::string &externalIface);

// Build argv for cleanup at jail teardown:
//   ipfw delete <ruleId>
//   ipfw nat <natId> delete
std::vector<std::string> buildIpfwRuleDeleteArgv(unsigned ruleId);
std::vector<std::string> buildIpfwNatDeleteArgv(unsigned natId);

} // namespace AutoFwPure
