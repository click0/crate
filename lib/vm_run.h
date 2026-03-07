// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// VM lifecycle management using libvirt (bhyve driver).
// Compile with WITH_LIBVIRT and link -lvirt.

#pragma once

#include "vm_spec.h"

#include <string>
#include <vector>

namespace VmRun {

// Whether libvirt support was compiled in.
bool available();

// Create and start a VM from spec.
// Returns a domain identifier (name).
std::string createVm(const std::string &name, const VmSpec::VmOptions &opts);

// Stop a running VM (graceful shutdown, then force if timeout).
void stopVm(const std::string &name, unsigned timeoutSec = 30);

// Destroy a VM immediately (force stop).
void destroyVm(const std::string &name);

// VM status info for listing.
struct VmInfo {
  std::string name;
  std::string state;    // "running", "shutoff", "paused"
  unsigned vcpu = 0;
  unsigned long memoryKiB = 0;
  double cpuPercent = 0;
};

// List all VMs managed by crate.
std::vector<VmInfo> listVms();

// Get info about a specific VM.
VmInfo getVmInfo(const std::string &name);

}
