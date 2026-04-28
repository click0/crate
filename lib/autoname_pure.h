// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Auto-generated names (timestamp-based) for snapshots and exports.
// Pure: only uses std::chrono + std::put_time.

#pragma once

#include <string>

namespace AutoNamePure {

// "20260428T114820" — used as ZFS snapshot name when user passes none.
std::string snapshotName();

// "<base>-20260428-114820.crate" — used by `crate export -o ...` default.
std::string exportName(const std::string &baseName);

}
