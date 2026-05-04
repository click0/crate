// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// `crate throttle <jail> --ingress RATE --egress RATE [--burst BYTES]
//                        [--queue N] [--clear] [--show]`
// — sets up dummynet token-bucket pipes for a running jail's
// network traffic. True sustained-rate-with-burst, in contrast
// to RCTL's hard cap (see `crate retune`).
//
// Pipe IDs are deterministic per jail (PoolPure-style) so that
// repeated invocations replace the previous config without
// orphaning rules. `--clear` removes the pipes + bind rules
// entirely.
//

#include "args.h"
#include "commands.h"
#include "jail_query.h"
#include "throttle_pure.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <iostream>
#include <string>

#define ERR(msg...) ERR2("throttle", msg)

namespace {

// Best-effort delete of an existing rule/pipe — used so a repeat
// `crate throttle ... --ingress 5Mbit/s` after an earlier
// `... --ingress 10Mbit/s` cleanly replaces the older config.
void softDelete(const std::vector<std::string> &argv,
                const std::string &what) {
  try {
    Util::execCommand(argv, what);
  } catch (...) {
    // Rule/pipe may simply not exist — fine.
  }
}

void clearJailThrottle(int jid) {
  // Order matters: rules first (they reference pipes), then pipes.
  for (bool egress : {false, true}) {
    softDelete(ThrottlePure::buildRuleDeleteArgv(
                 ThrottlePure::ruleIdForJail(jid, egress)),
               "ipfw delete (rule)");
  }
  for (bool egress : {false, true}) {
    softDelete(ThrottlePure::buildPipeDeleteArgv(
                 ThrottlePure::pipeIdForJail(jid, egress)),
               "ipfw pipe delete");
  }
}

void applyDirection(int jid, const std::string &jailIp,
                    const std::string &rate, const std::string &burst,
                    const std::string &queue, bool egress) {
  auto pipeId = ThrottlePure::pipeIdForJail(jid, egress);
  auto ruleId = ThrottlePure::ruleIdForJail(jid, egress);

  // Replace any prior config: drop the existing rule + pipe first.
  softDelete(ThrottlePure::buildRuleDeleteArgv(ruleId), "ipfw delete (rule)");
  softDelete(ThrottlePure::buildPipeDeleteArgv(pipeId), "ipfw pipe delete");

  // Configure pipe + bind.
  std::cerr << rang::fg::cyan
            << "throttle: configuring " << (egress ? "egress" : "ingress")
            << " pipe " << pipeId << " @ " << rate
            << (burst.empty() ? "" : (" burst " + burst))
            << (queue.empty() ? "" : (" queue " + queue))
            << rang::style::reset << std::endl;
  Util::execCommand(
    ThrottlePure::buildPipeConfigArgv(pipeId, rate, burst, queue),
    "ipfw pipe config");
  Util::execCommand(
    ThrottlePure::buildBindArgv(ruleId, pipeId, jailIp, egress),
    "ipfw add (bind)");
}

} // anon

bool throttleCommand(const Args &args) {
  if (args.throttleTarget.empty())
    ERR("the 'throttle' command requires a jail name (positional arg)")

  // Resolve jail.
  auto jail = JailQuery::getJailByName(args.throttleTarget);
  if (!jail) {
    try { jail = JailQuery::getJailByJid(std::stoi(args.throttleTarget)); }
    catch (...) {}
  }
  if (!jail) ERR("jail '" << args.throttleTarget << "' not found or not running")

  // --clear strips all throttle for the jail.
  if (args.throttleClear) {
    std::cerr << rang::fg::cyan
              << "throttle: clearing pipes for jail " << jail->name
              << " (jid " << jail->jid << ")"
              << rang::style::reset << std::endl;
    clearJailThrottle(jail->jid);
    if (!args.throttleShow) {
      std::cout << rang::fg::green
                << "throttle: cleared for " << jail->name
                << rang::style::reset << std::endl;
      return true;
    }
  }

  // Build + validate spec.
  ThrottlePure::ThrottleSpec spec;
  spec.ingressRate  = args.throttleIngressRate;
  spec.ingressBurst = args.throttleIngressBurst;
  spec.egressRate   = args.throttleEgressRate;
  spec.egressBurst  = args.throttleEgressBurst;
  spec.queue        = args.throttleQueue;
  if (auto e = ThrottlePure::validateSpec(spec); !e.empty())
    ERR(e)

  // --show alone (no config + no clear): just dump current pipe state.
  if (args.throttleShow && !args.throttleClear &&
      !ThrottlePure::hasAnyThrottle(spec)) {
    for (bool egress : {false, true}) {
      auto pipeId = ThrottlePure::pipeIdForJail(jail->jid, egress);
      try {
        auto out = Util::execCommandGetOutput(
          ThrottlePure::buildPipeShowArgv(pipeId), "ipfw pipe show");
        std::cout << "--- " << (egress ? "egress" : "ingress")
                  << " (pipe " << pipeId << ") ---\n" << out;
      } catch (...) {
        std::cout << "--- " << (egress ? "egress" : "ingress")
                  << " (pipe " << pipeId << ") --- (no pipe configured)\n";
      }
    }
    return true;
  }

  if (!ThrottlePure::hasAnyThrottle(spec))
    ERR("at least one of --ingress, --egress, --clear, or --show is required")

  // Validate jail IP (we use it in `from`/`to` clauses).
  if (auto e = ThrottlePure::validateIp(jail->ip4); !e.empty())
    ERR("jail '" << jail->name << "' has no usable IPv4 address: " << e)

  // Apply per direction.
  if (!spec.ingressRate.empty())
    applyDirection(jail->jid, jail->ip4,
                   spec.ingressRate, spec.ingressBurst, spec.queue,
                   /*egress*/false);
  if (!spec.egressRate.empty())
    applyDirection(jail->jid, jail->ip4,
                   spec.egressRate, spec.egressBurst, spec.queue,
                   /*egress*/true);

  if (args.throttleShow) {
    for (bool egress : {false, true}) {
      auto pipeId = ThrottlePure::pipeIdForJail(jail->jid, egress);
      try {
        auto out = Util::execCommandGetOutput(
          ThrottlePure::buildPipeShowArgv(pipeId), "ipfw pipe show");
        std::cout << "--- " << (egress ? "egress" : "ingress")
                  << " (pipe " << pipeId << ") ---\n" << out;
      } catch (...) {}
    }
  }

  std::cout << rang::fg::green
            << "throttle: " << jail->name << " (jid " << jail->jid << ")"
            << (spec.ingressRate.empty() ? "" : (" ingress=" + spec.ingressRate))
            << (spec.egressRate.empty()  ? "" : (" egress="  + spec.egressRate))
            << rang::style::reset << std::endl;
  return true;
}
