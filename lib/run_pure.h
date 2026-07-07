// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Tiny pure helpers extracted from lib/run.cpp and lib/run_net.cpp.
// Both are used by lots of jail-spawning code paths but are themselves
// simple string / env-var manipulations.

#pragma once

#include <string>

namespace RunPure {

// Render argv as a single shell-safe space-separated string.
// Used to log the original command line.
std::string argsToString(int argc, char **argv);

// Read CRATE_* env var, parse as unsigned, fall back to default on
// missing or unparseable value.
unsigned envOrDefault(const char *name, unsigned def);

// 1.1.22: validate a `cron/user` spec field before it is used to build
// the crontab path (`/var/cron/tabs/<user>`) and a `sh -c "chmod ...
// <user>"` string. Both are root-run in the setuid build, so an
// unvalidated value gives path traversal (`../../etc/cron.d/pwn`) and
// shell injection. Constrain to a POSIX-ish username: [A-Za-z0-9_-],
// 1..32 chars, no leading '-'. Empty is accepted unchanged (caller's
// existing default handling). Returns "" on success.
std::string validateCronUser(const std::string &user);

}
