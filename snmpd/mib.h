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

// Run one iteration of the AgentX dispatcher: read at most one
// incoming PDU, dispatch it (Get/GetNext) and send the response.
// Returns true if a PDU was processed, false on no input or error.
// Called from main loop with a short select() timeout.
bool dispatchOnce(int timeoutMs);

// Clean shutdown
void shutdownAgentX();

}
