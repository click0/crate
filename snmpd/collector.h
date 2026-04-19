// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Metrics collector — gathers container state from jls, rctl, GUI registry.
// Runs periodically in the main loop, results cached for SNMP GET.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace CrateSnmp {

struct ContainerMetrics {
  std::string name;
  int jid = 0;
  int state = 0;           // 0=stopped, 1=running, 2=starting, 3=dying
  int cpuPct = 0;          // CPU% × 100
  uint64_t memKB = 0;      // RSS in KB
  uint64_t netRx = 0;      // bytes received
  uint64_t netTx = 0;      // bytes transmitted
  uint64_t uptimeTicks = 0; // hundredths of a second
  int vncPort = 0;
  int wsPort = 0;
  std::string guiMode;
};

class Collector {
public:
  void collect();
  void checkTraps();

  const std::vector<ContainerMetrics>& containers() const { return containers_; }
  unsigned totalCount() const { return containers_.size(); }
  unsigned runningCount() const;

private:
  std::vector<ContainerMetrics> containers_;
  std::map<std::string, int> prevStates_; // for trap detection
};

}
