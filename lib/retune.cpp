// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// `crate retune <jail> --rctl KEY=VAL [--rctl ...] [--show]`
// — live RCTL adjustment for a running jail. No restart required;
// the jail's in-memory state survives. Pure validation +
// argv-building lives in lib/retune_pure.{h,cpp}; this file is
// the I/O glue around `rctl(8)`.
//

#include "args.h"
#include "commands.h"
#include "jail_query.h"
#include "privops_client.h"
#include "retune_pure.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <iostream>
#include <string>

#define ERR(msg...) ERR2("retune", msg)

bool retuneCommand(const Args &args) {
  if (args.retuneTarget.empty())
    ERR("the 'retune' command requires a jail name (positional arg)")

  // Build the pair list from --rctl flags.
  std::vector<RetunePure::RctlPair> pairs;
  pairs.reserve(args.retunePairs.size());
  for (auto &raw : args.retunePairs) {
    auto eq = raw.find('=');
    if (eq == std::string::npos)
      ERR("--rctl must be KEY=VALUE, got '" << raw << "'")
    pairs.push_back({raw.substr(0, eq), raw.substr(eq + 1)});
  }

  // Allow `--show` alone (no --rctl): just dump usage.
  if (pairs.empty() && !args.retuneShow)
    ERR("at least one --rctl KEY=VALUE pair is required (or use --show alone)")

  if (auto e = RetunePure::validatePairs(pairs); !e.empty() && !pairs.empty())
    ERR(e)

  // --clear KEY ... is also handled here — same validation lane.
  for (auto &k : args.retuneClear) {
    if (auto e = RetunePure::validateRctlKey(k); !e.empty())
      ERR("--clear: " << e)
  }

  // Resolve jail.
  auto jail = JailQuery::getJailByName(args.retuneTarget);
  if (!jail) {
    try { jail = JailQuery::getJailByJid(std::stoi(args.retuneTarget)); }
    catch (...) {}
  }
  if (!jail) ERR("jail '" << args.retuneTarget << "' not found or not running")

  // 0.9.15: detect privops socket. If present (CRATE_PRIVOPS_SOCKET
  // env or default path), delegate clear/set verbs to crated via
  // libnv. Otherwise the existing rctl(8) exec path runs unchanged
  // (legacy setuid mode).
  std::string privopsSocket = PrivOpsClient::detectSocketPath();

  // Pre-show (so the operator can see the before-state in logs).
  if (args.retuneShow) {
    std::cerr << rang::fg::cyan << "retune: rctl usage BEFORE:" << rang::style::reset << std::endl;
    auto out = Util::execCommandGetOutput(RetunePure::buildShowArgv(jail->jid),
                                          "rctl -u (before)");
    std::cout << out;
  }

  // Apply --clear first so a "clear then re-set with new value"
  // sequence doesn't error out on a duplicate rule.
  for (auto &k : args.retuneClear) {
    std::cerr << rang::fg::cyan
              << "retune: clearing jail:" << jail->jid << ":" << k << ":deny"
              << rang::style::reset << std::endl;
    if (!privopsSocket.empty()) {
      // Delegate via libnv → crated
      auto resp = PrivOpsClient::sendRequest(privopsSocket,
          PrivOpsClient::buildClearRctl(jail->jid, k));
      if (!resp.transportError.empty() || resp.status >= 400) {
        // Soft-fail (matches rctl(8) exec behaviour). Log and
        // continue — caller asked for "clear and continue".
        std::cerr << rang::fg::yellow
                  << "retune: --clear " << k << " ignored: "
                  << (resp.transportError.empty() ? resp.body
                                                  : resp.transportError)
                  << rang::style::reset << std::endl;
      }
    } else {
      try {
        Util::execCommand(RetunePure::buildClearArgv(jail->jid, k),
                          "rctl -r");
      } catch (const std::exception &e) {
        std::cerr << rang::fg::yellow
                  << "retune: --clear " << k << " ignored: " << e.what()
                  << rang::style::reset << std::endl;
      }
    }
  }

  // Apply --rctl pairs.
  for (auto &p : pairs) {
    std::cerr << rang::fg::cyan
              << "retune: setting jail:" << jail->jid << ":" << p.key
              << ":deny=" << p.rawValue
              << rang::style::reset << std::endl;
    if (!privopsSocket.empty()) {
      auto resp = PrivOpsClient::sendRequest(privopsSocket,
          PrivOpsClient::buildSetRctl(jail->jid, p.key, p.rawValue));
      if (!resp.transportError.empty())
        ERR("privops: " << resp.transportError)
      if (resp.status >= 400)
        ERR("privops set_rctl failed (status " << resp.status
            << "): " << resp.body)
    } else {
      Util::execCommand(RetunePure::buildSetArgv(jail->jid, p),
                        "rctl -a");
    }
  }

  // Post-show.
  if (args.retuneShow) {
    std::cerr << rang::fg::cyan << "retune: rctl usage AFTER:" << rang::style::reset << std::endl;
    auto out = Util::execCommandGetOutput(RetunePure::buildShowArgv(jail->jid),
                                          "rctl -u (after)");
    std::cout << out;
  }

  std::cout << rang::fg::green
            << "retune: " << jail->name << " (jid " << jail->jid << ") — "
            << pairs.size() << " rule(s) set, "
            << args.retuneClear.size() << " cleared"
            << rang::style::reset << std::endl;
  return true;
}
