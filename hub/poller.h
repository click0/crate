// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Node poller — periodically fetches /api/v1/containers and /api/v1/host
// from each configured crated instance via HTTP/TLS.

#pragma once

#include "store.h"

#include <atomic>
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

// Load node list from YAML config file
std::vector<NodeConfig> loadNodes(const std::string &configPath);

class Poller {
public:
  Poller(const std::vector<NodeConfig> &nodes, Store &store);

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
