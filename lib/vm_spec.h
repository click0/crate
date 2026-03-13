// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// VM (bhyve/libvirt) container spec: YAML parsing for type: vm.

#pragma once

#include <string>
#include <vector>

namespace VmSpec {

struct DisplayOptions {
  std::string mode = "vnc";       // vnc | novnc | virtio-gpu
  unsigned port = 0;              // 0 = auto-assign
  std::string resolution = "1024x768";
  bool virgl = false;             // virglrenderer for 3D
};

struct NetworkOptions {
  std::string type = "virtio-net"; // virtio-net | e1000
  bool rxcsum = true;
  bool txcsum = true;
  bool tso = false;                // off by default for bridge compat
};

// Shared volume mount via virtio-9p or NFS (for jail<->VM shared storage)
//
// shareMethod selects the transport:
//   "9p"  — virtio-9p (Plan 9 filesystem passthrough via hypervisor).
//           Works out of the box with bhyve; requires 9p kernel support
//           in the guest (CONFIG_NET_9P_VIRTIO on Linux, mount_9p on FreeBSD).
//   "nfs" — NFS export from host to guest over the shared bridge network.
//           Requires an NFS server running on the host and the host path
//           exported via /etc/exports (e.g. "hostPath -alldirs -network <bridge_subnet>").
//           The guest must have an NFS client and mount via:
//             mount -t nfs <host_bridge_ip>:hostPath /mnt/tag
//           NFS is the fallback when 9p is unsupported by the guest OS.
struct VirtioFsMount {
  std::string hostPath;            // host directory to share
  std::string tag;                 // 9p share tag (mount_9p <tag> in guest)
  bool readOnly = false;
  std::string shareMethod = "9p";  // "9p" or "nfs"
};

struct VmOptions {
  std::string memory = "1G";
  unsigned vcpu = 1;
  std::string disk;                // /dev/zvol/... or disk image path
  std::string storageType = "nvme"; // nvme | virtio-blk | ahci-hd | virtio-scsi
  std::string boot = "uefi";       // uefi | bios
  bool virtioRng = true;           // /dev/random via host entropy
  bool memoryBalloon = false;

  DisplayOptions display;
  NetworkOptions network;

  // Audio (FreeBSD 15+)
  std::string audio;               // "" | "virtio-sound"

  // Shared bridge: connect VM tap to an existing bridge (for jail<->VM networking)
  std::string sharedBridge;        // e.g. "bridge0" — if set, VM tap added to this bridge
  std::string sharedBridgeIp;      // static IP for VM on the bridge (CIDR)

  // Shared volumes via virtio-9p (for jail<->VM shared storage)
  std::vector<VirtioFsMount> sharedVolumes;
};

// Parse vm: section from a YAML node.
// Forward-declared; implementation depends on yaml-cpp.
VmOptions parseVmOptions(const void *yamlNode);

// Generate libvirt domain XML from VmOptions.
std::string generateDomainXml(const std::string &name, const VmOptions &opts);

}
