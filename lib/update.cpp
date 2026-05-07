// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// `crate update <jail> --pkg-only [-n | -y]` — in-place pkg upgrade
// inside a running jail. Closes the medium-priority TODO item.
//
// Pre-0.8.41, operators wanting to pick up new package versions had
// to `crate stop` + edit the spec / use a fresh tag + `crate run`,
// losing session state and warm caches. The `--pkg-only` variant
// runs `pkg upgrade` directly inside the jail via jexec(8) — same
// pattern the spec's `pkg:` install path uses at create time.
//
// Why `--pkg-only` is mandatory in this release:
//   Full base-system update touches /usr/lib, /usr/sbin, /lib while
//   the jail is using them — needs a snapshot+rollback dance plus
//   restart. That's a bigger surface (tracked separately in TODO);
//   this release commits to pkg-only so the contract is clear.
//
// Output / safety:
//   * --dry-run lists pending upgrades without applying anything
//     (passes `-n` to pkg upgrade)
//   * Without -y, pkg's interactive prompt fires inside the jail
//     and the operator confirms there. -y skips the prompt.
//   * Per-jail audit log entry just like other mutating commands.
//

#include "args.h"
#include "commands.h"
#include "jail_query.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <iostream>
#include <vector>

#define ERR(msg...) ERR2("update", msg)

bool updateCommand(const Args &args) {
  if (args.updateTarget.empty())
    ERR("the 'update' command requires a jail name (positional arg)")
  if (!args.updatePkgOnly)
    ERR("`crate update` currently requires --pkg-only. Full "
        "base-system update is tracked separately; only pkg "
        "upgrade is implemented in 0.8.41.")

  auto jail = JailQuery::getJailByName(args.updateTarget);
  if (!jail) {
    try {
      int jid = std::stoi(args.updateTarget);
      jail = JailQuery::getJailByJid(jid);
    } catch (...) {}
  }
  if (!jail)
    ERR("jail '" << args.updateTarget << "' not found or not running")

  std::cerr << rang::fg::cyan
            << "update: pkg upgrade in jail '" << jail->name
            << "' (jid " << jail->jid << ")"
            << (args.updateDryRun ? " (dry-run)" : "")
            << rang::style::reset << std::endl;

  // Build pkg argv. We let pkg(8) inside the jail invoke its own
  // `pkg update` for catalog refresh — `pkg upgrade` does that
  // implicitly unless -U is passed. So `pkg upgrade [-n] [-y]` is
  // sufficient and matches what an operator would type by hand
  // inside `jexec <jid> /bin/sh`.
  std::vector<std::string> argv = {CRATE_PATH_PKG, "upgrade"};
  if (args.updateDryRun)    argv.push_back("-n");
  if (args.updateAssumeYes) argv.push_back("-y");

  int status = JailExec::execInJail(jail->jid, argv, "root",
                                    "pkg upgrade in jail");
  int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

  if (rc != 0) {
    std::cerr << rang::fg::red
              << "update: pkg upgrade returned non-zero (" << rc << ")"
              << rang::style::reset << std::endl;
    return false;
  }
  if (args.updateDryRun) {
    std::cout << rang::fg::yellow
              << "update: dry-run complete; nothing applied"
              << rang::style::reset << std::endl;
  } else {
    std::cout << rang::fg::green
              << "update: pkg upgrade succeeded in '" << jail->name << "'"
              << rang::style::reset << std::endl;
  }
  return true;
}
