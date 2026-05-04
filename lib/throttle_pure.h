// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for `crate throttle` — true token-bucket network
// rate limiting via FreeBSD's dummynet(4) accessed through ipfw(8).
// Sister to `crate retune` (0.7.6) which targets RCTL — that's a
// hard cap, this is sustained-rate-with-burst, the kind operators
// reach for when they don't want a torrent client starving the
// IDE container of network bandwidth.
//
// Mechanism:
//   ipfw pipe <pipeId> config bw <rate> burst <burst> queue <queue>
//   ipfw add <ruleId> pipe <pipeId> ip from <jailIp> to any out  (egress)
//   ipfw add <ruleId> pipe <pipeId> ip from any to <jailIp> in   (ingress)
//
// `bw` is the sustained rate (Firecracker's "refill rate"),
// `burst` is the bucket capacity (Firecracker's "size"). Together
// they form a textbook token bucket.
//

#include <cstdint>
#include <string>
#include <vector>

namespace ThrottlePure {

// --- Validators ---

// Validate a rate string in ipfw pipe(8) form. Accepts:
//   "10Mbit/s", "100Kbit/s", "1Gbit/s"  (bit/s units)
//   "10MB/s", "100KB/s"                  (byte/s — uppercase B)
//   "10000"                               (bytes/s, no suffix)
// We forbid the bare "10M" form to avoid bit-vs-byte confusion;
// ipfw itself accepts both but ambiguity bites operators.
// Returns "" on success.
std::string validateRate(const std::string &rate);

// Validate a burst size: "1MB", "100KB", "100000". Same alphabet
// as ipfw burst takes (bytes only — no /s suffix). Empty string
// allowed → no burst (strict-rate).
std::string validateBurst(const std::string &burst);

// Validate a queue size. Either a slot count (plain integer 1..1000)
// or a byte size with B suffix ("100KB"). Empty allowed (default
// dummynet queue).
std::string validateQueue(const std::string &queue);

// Validate an IPv4 address string used to bind the pipe rule.
std::string validateIp(const std::string &ip);

// --- Pipe ID allocation ---

// Map a jail JID + direction to a deterministic pipe ID. Two pipes
// per jail: one for ingress, one for egress. Range starts at
// kPipeBase to leave the low IDs for operator-defined pipes.
constexpr unsigned kPipeBase = 10000;

unsigned pipeIdForJail(int jid, bool egress);

// Companion ipfw rule ID — same allocation strategy. Distinct
// from pipe IDs so an operator listing rules sees the correspondence.
constexpr unsigned kRuleBase = 20000;

unsigned ruleIdForJail(int jid, bool egress);

// --- Spec ---

struct ThrottleSpec {
  std::string ingressRate;   // "10Mbit/s" — empty if no ingress throttle
  std::string ingressBurst;
  std::string egressRate;    // "5Mbit/s"  — empty if no egress throttle
  std::string egressBurst;
  std::string queue;         // optional, applies to both directions
};

// Validate the whole spec (delegates to per-field validators).
std::string validateSpec(const ThrottleSpec &s);

// True iff at least one direction has a non-empty rate.
bool hasAnyThrottle(const ThrottleSpec &s);

// --- Argv builders ---

// `ipfw pipe <id> config bw <rate> [burst <burst>] [queue <queue>]`
std::vector<std::string> buildPipeConfigArgv(unsigned pipeId,
                                              const std::string &rate,
                                              const std::string &burst,
                                              const std::string &queue);

// `ipfw add <ruleId> pipe <pipeId> ip from <jailIp> to any out`
//                                    or
// `ipfw add <ruleId> pipe <pipeId> ip from any to <jailIp> in`
std::vector<std::string> buildBindArgv(unsigned ruleId,
                                        unsigned pipeId,
                                        const std::string &jailIp,
                                        bool egress);

// `ipfw delete <ruleId>` — remove the bind rule.
std::vector<std::string> buildRuleDeleteArgv(unsigned ruleId);

// `ipfw pipe <pipeId> delete` — remove the pipe.
std::vector<std::string> buildPipeDeleteArgv(unsigned pipeId);

// `ipfw pipe show <pipeId>` — for `crate throttle --show`.
std::vector<std::string> buildPipeShowArgv(unsigned pipeId);

} // namespace ThrottlePure
