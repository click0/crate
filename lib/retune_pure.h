// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for `crate retune` — live RCTL adjustment for a
// running jail without a restart. Operators throttle a runaway
// container (a torrent client suddenly sucking all the disk
// throughput) without losing its in-memory state.
//
// Usage on the runtime side:
//
//   crate retune myjail \
//       --rctl pcpu=20 \
//       --rctl writebps=1M \
//       --rctl readiops=500
//
// Each --rctl flag becomes one `rctl -a jail:<jid>:<key>:deny=<val>`
// invocation. The pure module owns:
//   - the whitelist of allowed RCTL keys (we don't pass arbitrary
//     keys to rctl(8) — typos would give the user a misleading
//     "rule already exists" instead of a clean "unknown key")
//   - human-friendly value parsing (`10M` → 10485760)
//   - argv builders for `rctl -a` (set) and `rctl -r` (remove)
//

#include <cstdint>
#include <string>
#include <vector>

namespace RetunePure {

// One key=value pair from the CLI.
struct RctlPair {
  std::string key;       // "pcpu", "writebps", ...
  std::string rawValue;  // operator-supplied text, possibly with K/M/G/T suffix
};

// --- Validators ---

// Whitelist of RCTL resource keys we accept. Mirrors what
// lib/run_jail.cpp's applyRctlLimits sets at jail-create time
// plus the I/O subset that operators most often need to retune.
// Returns "" on success.
std::string validateRctlKey(const std::string &key);

// Validate the operator-supplied value against the key's expected
// kind (numeric vs. byte rate vs. percentage).
//   - pcpu:   integer 0..100, no suffix
//   - *bps:   integer with optional K/M/G/T suffix (1024-based,
//             matches rctl(8)'s humanize_number convention)
//   - *iops:  integer, no suffix (operations per second)
//   - memoryuse / vmemoryuse: integer with K/M/G/T suffix
//   - maxproc / openfiles / nthr: integer, no suffix
// Returns "" on success.
std::string validateRctlValue(const std::string &key,
                              const std::string &rawValue);

// Walk a list of pairs and return the first failure, or "" if all
// pass.  Errors include the offending pair index for multi-flag
// invocations.
std::string validatePairs(const std::vector<RctlPair> &pairs);

// --- Human-readable size parser ---

// Parse "10M" / "1.5G" / "500K" / "100" into the numeric value.
// Suffixes K/M/G/T are 1024-based (rctl convention). Lowercase
// k/m/g/t accepted. Decimal points accepted: "1.5G" =
// 1610612736. Returns -1 on parse error (caller already
// validated, but defensive).
long parseHumanSize(const std::string &s);

// --- Argv builders ---

// `rctl -a jail:<jid>:<key>:deny=<value>` — the runtime feeds
// the operator-supplied raw value through unchanged (rctl(8)
// itself accepts the K/M/G/T suffixes, so we don't need to
// numericise on this side).
std::vector<std::string> buildSetArgv(int jid, const RctlPair &p);

// `rctl -r jail:<jid>:<key>:deny` — used by `--clear KEY` to
// drop a rule entirely instead of setting a new value.
std::vector<std::string> buildClearArgv(int jid, const std::string &key);

// `rctl -u jail:<jid>` — used by `crate retune --show <jail>`
// to dump current usage before/after the change so the operator
// sees the effect.
std::vector<std::string> buildShowArgv(int jid);

} // namespace RetunePure
