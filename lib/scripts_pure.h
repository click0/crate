// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers extracted from lib/scripts.cpp for unit testing.

#pragma once

#include <string>
#include <vector>

namespace ScriptsPure {

// Escape a script body for embedding inside single-quoted /bin/sh -c '...'.
// Inside single quotes only the single quote itself needs escaping.
std::string escape(const std::string &script);

// 1.1.75: where `crate run` executes a `scripts:` section. Every section
// used to run as `chroot <jail tree> /bin/sh` as HOST root: the host's
// network, no jail limits, and once the jail's processes had run, its
// root could have replaced /bin/sh — or anything the hook calls — which
// then ran as host root and could leave the chroot. Under rootless
// chroot(8) was EPERM.
//   InJail      — the jail exists: run inside it, as its root
//                 (jail_attach; privops exec_in_jail under rootless).
//   ThrowAway   — before the jail exists (run:begin,
//                 run:before-create-jail) or after it is gone
//                 (run:after-remove-jail): a short-lived jail(8) on the
//                 same tree, without vnet, the host's addresses
//                 inherited so a hook can still reach the network.
//                 Root only.
// `crate create`'s sections (create:start, create:end) are not run by
// `crate run`; create.cpp keeps its chroot of the tree it just built.
enum class HookPlace { InJail, ThrowAway };
HookPlace hookPlace(const std::string &section);

// The sections of `scripts` that run in a throw-away jail, in run order
// ("" when none) — rootless refuses them up front.
std::string firstThrowAwaySection(const std::vector<std::string> &sections);

// argv of the throw-away jail for one hook command line:
//   jail -c path=<tree> ip4=inherit [ip6=inherit] command=/bin/sh -c <line>
// No name (the kernel names it by its jid), no persist: it is gone when
// the command exits, and jail(8)'s exit status is the command's.
std::vector<std::string> throwAwayJailArgv(const std::string &jailPath,
                                           const std::string &commandLine,
                                           bool inet6);

}
