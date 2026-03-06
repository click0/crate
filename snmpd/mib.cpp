// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// SNMP MIB implementation — AgentX subagent for CRATE-MIB.
//
// OID base: enterprises.60117 (crate project)
// Uses bsnmpd AgentX on FreeBSD, or net-snmp AgentX as fallback.
//
// TODO: Implement actual AgentX protocol.
// This file provides the interface and data structures;
// the AgentX wire protocol implementation is deferred to full implementation.

#include "mib.h"
#include "collector.h"

#include "util.h"

#include <mutex>
#include <iostream>

namespace CrateSnmp {

// Cached MIB data (updated by collector, read by AgentX handler)
static std::mutex g_mibMutex;
static std::vector<ContainerMetrics> g_containers;
static unsigned g_totalCount = 0;
static unsigned g_runningCount = 0;
static std::string g_version = "0.2.2";
static std::string g_hostname;

bool initAgentX(const std::string &socketPath) {
  // TODO: Open AgentX connection to bsnmpd
  // For bsnmpd: connect to Unix socket, send Open PDU
  // For net-snmp: use init_agent() API
  (void)socketPath;
  std::cerr << "crate-snmpd: WARNING: AgentX protocol not yet implemented — "
               "running in stub mode, no SNMP data will be exported" << std::endl;
  try {
    g_hostname = Util::getSysctlString("kern.hostname");
  } catch (...) {
    g_hostname = "unknown";
  }
  return true; // stub
}

void registerMib() {
  // TODO: Register OID subtree enterprises.60117
  // AgentX Register PDU for:
  //   .1.3.6.1.4.1.60117.1.1  crateVersion
  //   .1.3.6.1.4.1.60117.1.2  crateHostname
  //   .1.3.6.1.4.1.60117.1.3  crateContainerCount
  //   .1.3.6.1.4.1.60117.1.4  crateContainerRunning
  //   .1.3.6.1.4.1.60117.1.10 crateContainerTable
}

void updateMibData(const Collector &collector) {
  std::lock_guard<std::mutex> lock(g_mibMutex);
  g_containers = collector.containers();
  g_totalCount = collector.totalCount();
  g_runningCount = collector.runningCount();
}

void sendTrap(TrapType type, const std::string &containerName, int jid) {
  // TODO: Send AgentX Notify PDU
  // For now, log the event
  const char *typeName = "unknown";
  switch (type) {
  case TrapType::ContainerStarted: typeName = "started"; break;
  case TrapType::ContainerStopped: typeName = "stopped"; break;
  case TrapType::ContainerOOM:     typeName = "oom";     break;
  }
  std::cerr << "crate-snmpd: trap " << typeName
            << " container=" << containerName << " jid=" << jid << std::endl;
}

void shutdownAgentX() {
  // TODO: Send AgentX Close PDU
}

}
