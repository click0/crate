// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers for crate's per-jail diagnostic log paths.
// Production callers (lib/create.cpp, lib/util.cpp) handle the actual
// file I/O; these helpers compute filesystem-safe paths.

#pragma once

#include <string>

namespace LogPure {

// Replace characters that aren't safe in a filename ('/' and NUL) with
// '_'. Also collapse leading dots so the resulting name doesn't become
// hidden / "..". Caller-supplied names from running jails (e.g.
// hostnames) are otherwise trusted.
std::string sanitizeName(const std::string &name);

// Compose a log path:
//   <logsDir>/<kind>-<sanitized name>.log
// where `kind` is something like "create" or "run".
// `logsDir` and `kind` are taken verbatim — they're internal callers,
// not user input.
std::string createLogPath(const std::string &logsDir,
                          const std::string &kind,
                          const std::string &name);

}
