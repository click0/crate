// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure aggregation helpers for the hub web dashboard. The runtime
// side (`hub/api.cpp`) gathers raw `NodeStatus` records from the
// poller; this module converts them into summary numbers and a
// dashboard-friendly JSON shape, with no I/O.
//

#include <cstdint>
#include <string>
#include <vector>

namespace AggregatorPure {

// Minimal projection of `Poller::NodeStatus` so this module has no
// dependency on the runtime header (and tests can construct inputs
// trivially).
struct NodeView {
  std::string name;
  std::string host;
  bool reachable = false;
  // Number of containers the node reported (0 if unreachable or no
  // jails). We don't depend on the parsed JSON here — the caller
  // counts beforehand.
  unsigned containerCount = 0;
};

struct Summary {
  unsigned nodesTotal     = 0;
  unsigned nodesReachable = 0;
  unsigned nodesDown      = 0;
  unsigned containersTotal = 0;
};

// Compute summary across all nodes.
Summary summarise(const std::vector<NodeView> &nodes);

// Render the summary as a small JSON object suitable for the web
// dashboard's overview banner. Field order is stable so a diff-based
// test can pin it.
std::string renderSummaryJson(const Summary &s);

// Count top-level objects in a JSON array string. Used so the
// runtime can derive `containerCount` for each node from the raw
// JSON returned by `/api/v1/containers` without pulling in a JSON
// parser. Recognises:
//   - empty array `[]` → 0
//   - `[{...},{...}]` → 2
// Limitation (acceptable here): does not handle bracket characters
// embedded in strings — the daemon's container-list response uses
// safe field names. Returns 0 on malformed input.
unsigned countTopLevelObjects(const std::string &jsonArray);

} // namespace AggregatorPure
