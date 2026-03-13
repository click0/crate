// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Helper to integrate VM entries in stack orchestration.

#pragma once

#include <string>
#include <vector>
#include <map>

// Helper to integrate VM entries in stack orchestration.
// Returns the tap interface name for a VM connected to a bridge.
std::string getVmTapInterface(const std::string &vmName);

// Register a VM in the stack DNS and /etc/hosts.
// Called during stack-up for VM-type entries.
void registerVmInStack(const std::string &vmName,
                       const std::string &ip,
                       const std::string &bridgeIface);
