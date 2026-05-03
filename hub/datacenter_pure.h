// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure datacenter grouping helpers for crate-hub.
//
// Each NodeConfig gains an optional `datacenter:` string. Nodes
// without an explicit DC are placed in the "default" group. The
// hub's REST API gains:
//
//   GET /api/v1/datacenters
//
// returning per-DC reachability + container counts so the upcoming
// admin UI (deferred) can render a grouped node tree without
// re-deriving it client-side.
//
// All grouping/aggregation logic lives here; runtime callers in
// hub/api.cpp project Poller::NodeStatus into the lightweight
// `NodeView` defined in hub/aggregator_pure.h, then add the DC
// label to produce the per-DC summary.
//

#include "aggregator_pure.h"

#include <cstdint>
#include <string>
#include <vector>

namespace DatacenterPure {

// One row in the datacenters response.
struct DcView {
  AggregatorPure::NodeView node;
  std::string datacenter;
};

struct DcSummary {
  std::string name;
  unsigned nodesTotal     = 0;
  unsigned nodesReachable = 0;
  unsigned nodesDown      = 0;
  unsigned containersTotal = 0;
};

// Validate a datacenter name. Used at config-load time so a
// typo doesn't silently route a node into a phantom DC.
//   - non-empty, ≤ 32 chars
//   - allowed: [A-Za-z0-9._-]
//   - reserved: nothing right now (we accept "default" since that's
//     the implicit fallback and operators may want to make it
//     explicit).
// Returns "" on success.
std::string validateName(const std::string &name);

// Map an empty `datacenter:` string to the default sentinel name
// the hub uses internally. Centralises the "no-DC = default"
// convention so the runtime and tests agree.
std::string canonicalName(const std::string &raw);

// Produce one DcSummary per distinct datacenter, sorted by name.
// Mirrors `AggregatorPure::summarise` semantics: a node's
// containerCount is counted only if it is reachable.
std::vector<DcSummary> groupAndSummarise(const std::vector<DcView> &views);

// Render the datacenter list as the JSON shape the API returns:
//
//   [
//     {"name":"dc1","nodes_total":3,"nodes_reachable":3,
//      "nodes_down":0,"containers_total":17},
//     ...
//   ]
//
// Field order is stable for diff-friendly responses.
std::string renderJson(const std::vector<DcSummary> &dcs);

} // namespace DatacenterPure
