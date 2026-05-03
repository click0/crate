// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure decision module for the hub's HA (high-availability) policy.
// The runtime side (hub/api.cpp) feeds in:
//   * the operator's HA spec from crate-hub.conf
//     (`ha:` section: per-container primary + ordered partner list)
//   * the latest poller results (per-node reachable + how long it
//     has been unreachable, in seconds)
// and the pure side decides which migrations should happen now.
//
// The hub does NOT perform migrations itself — that would require
// it to hold admin tokens for the per-node daemons, which violates
// the 0.6.7 architecture (tokens stay in operator localStorage / a
// chmod-600 file). Instead the hub publishes a list of
// MigrationOrders via GET /api/v1/ha/orders, and an operator-side
// consumer (cron + crate migrate, or a future `crate ha-execute`)
// picks them up.
//
// This file owns:
//   * the data shapes (HaSpec, NodeView, MigrationOrder)
//   * the decision function (evaluateFailoverOrders)
//   * a JSON renderer for the API surface
//

#include <cstdint>
#include <string>
#include <vector>

namespace HaPure {

// One operator-declared HA policy: container X normally lives on
// `primaryNode`; if that node is down, fail over to the first
// reachable entry in `partnerNodes`. Order matters — list higher-
// priority hosts first.
struct HaSpec {
  std::string containerName;
  std::string primaryNode;
  std::vector<std::string> partnerNodes;
};

// Minimal projection of Poller::NodeStatus that the decision
// module needs. The runtime fills these in.
struct NodeView {
  std::string name;
  bool reachable = false;
  // Seconds the node has been unreachable. 0 if reachable or never
  // seen down. The poller computes this from a "first-down-at"
  // timestamp.
  long unreachableSeconds = 0;
};

// One concrete failover instruction for a consumer to execute.
struct MigrationOrder {
  std::string container;
  std::string fromNode;
  std::string toNode;
  // Free-form diagnostic for logs / API consumers.
  std::string reason;
};

// Decide which failovers should run *right now* given the spec
// and node status. `thresholdSeconds` is the operator-set window
// before a node is treated as down for HA purposes (defaults
// elsewhere; 60s is a reasonable starting point).
//
// Rules:
//   * Skip a HaSpec whose primary is reachable.
//   * Skip a HaSpec whose primary is unreachable but for less
//     than `thresholdSeconds` (avoids flapping).
//   * For an over-threshold-down primary, pick the first partner
//     in order that is currently reachable, emit an order.
//   * If all partners are unreachable, emit NO order (a partial
//     order would leave the container in limbo); the runtime
//     surfaces this via the `reason` field of an extra
//     placeholder order if it wants to.
//
// The decision is deterministic — same inputs always produce the
// same orders, so a poll-then-decide loop never thrashes.
std::vector<MigrationOrder>
evaluateFailoverOrders(const std::vector<HaSpec> &specs,
                       const std::vector<NodeView> &nodes,
                       long thresholdSeconds);

// Render an orders list as a JSON array body suitable for
// `/api/v1/ha/orders`. Stable shape:
//   [{"container":"...","from_node":"...","to_node":"...","reason":"..."}, ...]
std::string renderOrdersJson(const std::vector<MigrationOrder> &orders);

// Validate operator-declared HA spec entries. Returns "" on
// success; otherwise the first failure reason (with the
// container index for multi-spec files).
//   - containerName: alnum + `._-`, 1..64 chars
//   - primaryNode: alnum + `._-`, 1..64 chars
//   - partnerNodes: ≥1 entry; all alnum + `._-`; all distinct
//                   from primaryNode and from each other.
std::string validateSpecs(const std::vector<HaSpec> &specs);

} // namespace HaPure
