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

}
