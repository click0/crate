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

// Connect a VM's tap interface to a shared bridge (for jail<->VM networking).
// Called after VM creation to add the tap to the same bridge used by jails.
void connectToSharedBridge(const std::string &vmName,
                           const std::string &bridgeIface);

// Configure VM to use stack DNS service.
// Writes resolv.conf via virtio-9p shared directory or cloud-init.
void configureVmDns(const std::string &vmName, const std::string &dnsIp);

// Generate cloud-init user-data script that mounts 9p shares in the guest.
// Returns the path to the generated user-data file.
std::string generateCloudInitFor9p(const std::vector<VmSpec::VirtioFsMount> &volumes);

}
