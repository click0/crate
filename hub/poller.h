// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Node poller — periodically fetches /api/v1/containers and /api/v1/host
// from each configured crated instance via HTTP/TLS.

#pragma once

#include "ha_pure.h"
#include "store.h"

#include <atomic>
#include <ctime>
#include <mutex>
#include <string>
#include <vector>

namespace CrateHub {

struct NodeConfig {
  std::string name;        // display name
  std::string host;        // host:port (e.g. "host-01.example.com:9800")
  std::string tlsCert;     // client cert for mTLS (optional)
  std::string tlsKey;      // client key (optional)
  std::string token;       // Bearer token (optional)
  std::string datacenter;  // logical group name; empty -> "default"
};

// Load node list from YAML config file. The optional
// `outPollIntervalSec` out-parameter receives the value of the
// top-level `poll_interval` key (default 15 if missing). Same
// out-param shape as loadHaSpecs's `outThresholdSeconds`.
std::vector<NodeConfig> loadNodes(const std::string &configPath,
                                  unsigned *outPollIntervalSec = nullptr);

// Load operator HA specs from the same crate-hub.conf:
//   ha:
//     threshold_seconds: 60
//     specs:
//       - container: foo
//         primary: alpha
//         partners: [beta, gamma]
//
// Returns the parsed specs (possibly empty if no `ha:` section).
// The threshold value is written to `*outThresholdSeconds` if
// non-null; default 60 if missing.
std::vector<HaPure::HaSpec> loadHaSpecs(const std::string &configPath,
                                        long *outThresholdSeconds = nullptr);

class Poller {
public:
  Poller(const std::vector<NodeConfig> &nodes, Store &store,
         unsigned pollIntervalSec = 15);

  void run();   // blocking: poll loop
  void stop();

  // Get cached data for API
  struct NodeStatus {
    std::string name;
    std::string host;
    std::string datacenter;     // group label, mirrored from NodeConfig
    bool reachable = false;
    std::string hostInfo;       // raw JSON from /api/v1/host
    std::string containers;     // raw JSON from /api/v1/containers
    std::string lastError;
    // Wall-clock UNIX epoch when the node first became unreachable
    // in the current down-streak. 0 while reachable. Updated by
    // pollNode() at each cycle. Used by the HA decision module to
    // measure how long a node has been down.
    time_t firstDownAt = 0;
  };
  std::vector<NodeStatus> getNodeStatuses() const;

private:
  std::vector<NodeConfig> nodes_;
  Store &store_;
  std::atomic<bool> running_{true};
  unsigned pollIntervalSec_ = 15;

  std::vector<NodeStatus> statuses_;
  mutable std::mutex statusMutex_;

  void pollNode(const NodeConfig &node, NodeStatus &status);
};

}
