// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for hub-side container placement scheduling.
//
// Operators running multiple crate hosts behind a hub want a
// recommendation for "where should I put this next jail?". This
// module ranks nodes by container count (best proxy we have
// without daemon-side load metrics) and returns the least-loaded
// reachable node.
//
// No HTTP, no shell-out — feeds off the {name, host, reachable,
// containerCount} view that the existing AggregatorPure already
// computes. Tested in isolation.
//
// Anti-flap: the optional `currentNodeHint` param lets a caller
// say "the container is on node X today; don't migrate it unless
// the alternative is meaningfully better". Implemented as a
// 10% tolerance around the best score. Without the hint, we just
// pick the lowest-count reachable node.
//

#include <string>
#include <vector>

namespace SchedulingPure {

// View of one node in the cluster, with just what scheduling needs.
struct NodeView {
  std::string name;            // operator-facing display name
  std::string host;            // host:port for reachability
  bool        reachable = false;
  unsigned    containerCount = 0;
};

// One scheduling recommendation. `confidence` is a 0..100 hint
// for the operator: high when the chosen node is clearly less
// loaded than the next best, low when the spread is tight and
// the choice is borderline.
struct Recommendation {
  std::string targetName;      // chosen node name; empty if no candidate
  std::string targetHost;      // chosen node host:port
  unsigned    targetCount = 0;
  unsigned    runnerUpCount = 0;  // second-place count, for confidence calc
  int         confidence = 0;     // 0..100; 0 means "no candidate found"
  std::string rationale;          // human-readable one-liner
};

// Anti-flap tolerance: when the current host is within this
// fraction of the least-loaded host, prefer the current host
// (avoids ping-pong migrations under transient load).
//   currentCount <= bestCount * (1 + ANTI_FLAP_RATIO)
//     -> recommend keeping current
//   else
//     -> recommend the least-loaded
//
// Expressed as a percent so the test names read naturally.
constexpr int kAntiFlapPercent = 10;

// Pick the least-loaded reachable node. Unreachable nodes are
// always skipped. If `currentNodeHint` is set and matches a
// reachable node, the anti-flap rule applies; otherwise we
// pick the lowest-count reachable node outright.
//
// Returns {} (empty `targetName`, confidence 0) when:
//   - no reachable nodes
//   - all reachable nodes have an invalid count (shouldn't happen)
Recommendation pickLeastLoaded(
  const std::vector<NodeView> &nodes,
  const std::string &currentNodeHint = "");

// JSON renderer for the /api/v1/scheduling/least-loaded endpoint.
//   {
//     "target": "alpha",
//     "host": "alpha.example.com:9800",
//     "container_count": 3,
//     "runner_up_count": 5,
//     "confidence": 67,
//     "rationale": "..."
//   }
// or, on no-candidate:
//   {
//     "target": null,
//     "rationale": "no reachable nodes"
//   }
std::string renderRecommendationJson(const Recommendation &rec);

// 0.8.43: CLI helper plumbing. The `crate-hub schedule <jail>`
// subcommand wraps the curl + JSON-extract + `crate migrate`
// dance. Pure helpers below are the testable bits.

// Compose the least-loaded URL given a hub base URL and an
// optional currentNodeHint:
//   buildLeastLoadedUrl("http://hub:9810", "")     -> ".../least-loaded"
//   buildLeastLoadedUrl("http://hub:9810", "foo")  -> ".../least-loaded?current=foo"
// Trailing slash on hubUrl is tolerated. currentNodeHint is
// percent-encoded for the small subset of chars we expect in
// jail names ([A-Za-z0-9_-] passes through; anything else
// gets %HH).
std::string buildLeastLoadedUrl(const std::string &hubUrl,
                                const std::string &currentNodeHint);

// Pull `target` field from the endpoint's JSON body. Returns
// empty string when the field is null or absent. Handles both
//   "target":"alpha"
//   "target": "alpha"
//   "target":null
// without dragging in a full JSON parser (operator-controlled
// hub returns the format we render in renderRecommendationJson —
// stable, no need for general parsing).
std::string extractTargetField(const std::string &jsonBody);

// Pull `host` field — same pattern as extractTargetField.
std::string extractHostField(const std::string &jsonBody);

// Build the `crate migrate` argv to hand off to execv. Operator-
// supplied paths are NOT validated here — that's `crate migrate`'s
// job. We just compose the argv shape; this is the unit-test seam.
//   ["/usr/local/bin/crate", "migrate", "<jail>",
//    "--from", "<fromHost>", "--to", "<toHost>",
//    "--from-token-file", "<fromTok>", "--to-token-file", "<toTok>"]
// fromHost / toHost should already be in `host:port` form.
std::vector<std::string> buildMigrateArgv(const std::string &cratePath,
                                          const std::string &jail,
                                          const std::string &fromHost,
                                          const std::string &toHost,
                                          const std::string &fromTokenFile,
                                          const std::string &toTokenFile);

} // namespace SchedulingPure
