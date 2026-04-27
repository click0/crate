// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers used by lib/import.cpp. The shell-out portions
// (xz, tar, sha256) cannot be unit-tested without fixtures, but the
// inline parsing/validation steps live here and are testable.

#pragma once

#include <string>

namespace ImportPure {

// First-line .sha256 file format: "hexhash  filename" or "hexhash"
std::string parseSha256File(const std::string &line);

// Returns true iff any tar listing entry contains a ".." path component.
bool        archiveHasTraversal(const std::string &listing);

// Strips leading "./" and trailing slashes from a tar entry name.
std::string normalizeArchiveEntry(const std::string &entry);

}
