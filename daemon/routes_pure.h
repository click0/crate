// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for crated REST routes — formatting and validation
// logic that has no daemon-state or syscall dependencies, so it can
// be unit-tested cheaply on Linux.
//

#include <string>
#include <utility>
#include <vector>

namespace RoutesPure {

// --- Stats SSE event formatting ---

struct StatsInput {
  std::string name;
  int jid = 0;
  std::string ip;
  // RCTL key=value pairs as parsed from `rctl -u jail:<jid>`.
  // Values are emitted as JSON numbers if numeric, else as strings.
  std::vector<std::pair<std::string, std::string>> usage;
};

// Build one SSE frame: `data: <json>\n\n`. The JSON payload includes
// `name`, `jid`, `ip`, all `usage` entries, plus a `ts` field with
// the supplied UNIX epoch (so callers can drive the clock from
// tests). Strings inside `usage` keys/values are JSON-escaped.
std::string formatStatsSseEvent(const StatsInput &in, long unixEpoch);

// --- Snapshot name validation ---

// Validate a user-supplied snapshot name as accepted by the daemon's
// snapshot endpoints. Rules:
//   - Length 1..64.
//   - Allowed characters: letters, digits, '.', '_', '-'.
//   - Reserved: "." and ".." (filesystem-reserved); also bare "0" is
//     allowed since ZFS permits it.
// Returns "" on success; otherwise a one-line reason suitable for
// returning to the client as the `error` field.
std::string validateSnapshotName(const std::string &name);

// --- Tiny JSON body extraction ---

// Extract the value of a top-level string field from a small JSON
// object, e.g. extractNameField(R"({"name":"backup-1"})", "name")
// returns "backup-1". Returns "" if the field is absent, the body
// is empty, or the value is not a JSON string. This is intentionally
// minimal — the daemon's request bodies are tiny and we don't want
// to pull in a JSON parser.
//
// Quirks (documented for tests):
//   - Whitespace allowed around the colon and quotes.
//   - Backslash escapes (\", \\, \n) inside the value are decoded.
//   - No nested objects/arrays — first matching key at any depth
//     wins, which is acceptable given the daemon's controlled input.
std::string extractStringField(const std::string &body, const std::string &fieldName);

} // namespace RoutesPure
