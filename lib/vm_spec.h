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
};

// Parse vm: section from a YAML node.
// Forward-declared; implementation depends on yaml-cpp.
VmOptions parseVmOptions(const void *yamlNode);

// Generate libvirt domain XML from VmOptions.
std::string generateDomainXml(const std::string &name, const VmOptions &opts);

}
