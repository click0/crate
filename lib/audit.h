// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Append-only audit log for state-changing crate commands. The bulk
// of the formatting logic lives in lib/audit_pure.cpp; this side does
// the file I/O and ties together with Config / sysctl.

#pragma once

#include <string>

class Args;

namespace Audit {

// Log "started" — call after Args::validate() succeeds and before
// the command body runs. argc/argv are needed to record the original
// invocation; outcome is empty here, set to "started".
void logStart(int argc, char **argv, const Args &args);

// Log final outcome. If `errMsg` is empty, writes "ok"; otherwise
// "failed: <errMsg>".
void logEnd(int argc, char **argv, const Args &args, const std::string &errMsg);

}
