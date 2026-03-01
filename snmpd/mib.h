// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// SNMP MIB registration and data updates.
// Uses bsnmpd AgentX API (FreeBSD native) to expose CRATE-MIB.

#pragma once

#include <string>

namespace CrateSnmp {

class Collector;

enum class TrapType {
  ContainerStarted,
  ContainerStopped,
  ContainerOOM
};

// Initialize AgentX connection to bsnmpd/net-snmp
bool initAgentX(const std::string &socketPath);

// Register all CRATE-MIB OIDs
void registerMib();

// Update MIB data from latest collector results
void updateMibData(const Collector &collector);

// Send an SNMP notification (trap)
void sendTrap(TrapType type, const std::string &containerName, int jid);

// Clean shutdown
void shutdownAgentX();

}
