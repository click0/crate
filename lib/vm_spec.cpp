// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// VM spec YAML parsing and libvirt XML generation.

#include "vm_spec.h"

#include <yaml-cpp/yaml.h>

#include <sstream>

namespace VmSpec {

VmOptions parseVmOptions(const void *yamlNodePtr) {
  VmOptions opts;
  auto &node = *static_cast<const YAML::Node*>(yamlNodePtr);

  if (!node.IsMap()) return opts;

  if (node["memory"])       opts.memory = node["memory"].as<std::string>();
  if (node["vcpu"])         opts.vcpu = node["vcpu"].as<unsigned>();
  if (node["disk"])         opts.disk = node["disk"].as<std::string>();
  if (node["storage"])      opts.storageType = node["storage"].as<std::string>();
  if (node["boot"])         opts.boot = node["boot"].as<std::string>();
  if (node["virtio_rng"])   opts.virtioRng = node["virtio_rng"].as<bool>();
  if (node["memory_balloon"]) opts.memoryBalloon = node["memory_balloon"].as<bool>();
  if (node["audio"])        opts.audio = node["audio"].as<std::string>();

  if (node["display"] && node["display"].IsMap()) {
    auto d = node["display"];
    if (d["mode"])       opts.display.mode = d["mode"].as<std::string>();
    if (d["port"])       opts.display.port = d["port"].as<unsigned>();
    if (d["resolution"]) opts.display.resolution = d["resolution"].as<std::string>();
    if (d["virgl"])      opts.display.virgl = d["virgl"].as<bool>();
  }

  if (node["network"] && node["network"].IsMap()) {
    auto n = node["network"];
    if (n["type"])    opts.network.type = n["type"].as<std::string>();
    if (n["rxcsum"])  opts.network.rxcsum = n["rxcsum"].as<bool>();
    if (n["txcsum"])  opts.network.txcsum = n["txcsum"].as<bool>();
    if (n["tso"])     opts.network.tso = n["tso"].as<bool>();
  } else if (node["network"] && node["network"].IsScalar()) {
    opts.network.type = node["network"].as<std::string>();
  }

  // Shared bridge for jail<->VM networking (§27.3)
  if (node["shared_bridge"]) opts.sharedBridge = node["shared_bridge"].as<std::string>();
  if (node["shared_bridge_ip"]) opts.sharedBridgeIp = node["shared_bridge_ip"].as<std::string>();

  // Shared volumes via virtio-9p (§27.3)
  if (node["shared_volumes"] && node["shared_volumes"].IsSequence()) {
    for (auto v : node["shared_volumes"]) {
      VirtioFsMount mount;
      if (v.IsMap()) {
        if (v["host_path"])     mount.hostPath = v["host_path"].as<std::string>();
        if (v["tag"])           mount.tag = v["tag"].as<std::string>();
        if (v["read_only"])     mount.readOnly = v["read_only"].as<bool>();
        if (v["share_method"])  mount.shareMethod = v["share_method"].as<std::string>();
      } else if (v.IsScalar()) {
        // Format: "host_path:tag[:ro]"
        auto str = v.as<std::string>();
        auto c1 = str.find(':');
        if (c1 != std::string::npos) {
          mount.hostPath = str.substr(0, c1);
          auto rest = str.substr(c1 + 1);
          auto c2 = rest.rfind(':');
          if (c2 != std::string::npos && rest.substr(c2 + 1) == "ro") {
            mount.readOnly = true;
            mount.tag = rest.substr(0, c2);
          } else {
            mount.tag = rest;
          }
        }
      }
      if (!mount.hostPath.empty() && !mount.tag.empty())
        opts.sharedVolumes.push_back(std::move(mount));
    }
  }

  return opts;
}

// Parse memory string (e.g. "2G", "512M") to KiB for libvirt.
static unsigned long memoryToKiB(const std::string &mem) {
  unsigned long val = 0;
  char suffix = 0;
  std::istringstream iss(mem);
  iss >> val >> suffix;
  switch (suffix) {
  case 'G': case 'g': return val * 1024 * 1024;
  case 'M': case 'm': return val * 1024;
  case 'K': case 'k': return val;
  default: return val * 1024; // assume MiB
  }
}

std::string generateDomainXml(const std::string &name, const VmOptions &opts) {
  std::ostringstream xml;
  auto memKiB = memoryToKiB(opts.memory);

  xml << "<domain type='bhyve'>\n"
      << "  <name>" << name << "</name>\n"
      << "  <memory unit='KiB'>" << memKiB << "</memory>\n"
      << "  <vcpu>" << opts.vcpu << "</vcpu>\n"
      << "  <os>\n";

  if (opts.boot == "uefi")
    xml << "    <type>hvm</type>\n"
        << "    <loader readonly='yes' type='pflash'>/usr/local/share/uefi-firmware/BHYVE_UEFI.fd</loader>\n";
  else
    xml << "    <type>hvm</type>\n";

  xml << "  </os>\n"
      << "  <devices>\n";

  // Disk
  if (!opts.disk.empty()) {
    xml << "    <disk type='block' device='disk'>\n"
        << "      <driver name='file' type='raw'/>\n"
        << "      <source dev='" << opts.disk << "'/>\n";

    if (opts.storageType == "nvme")
      xml << "      <target dev='nvme0' bus='nvme'/>\n";
    else if (opts.storageType == "virtio-blk")
      xml << "      <target dev='vda' bus='virtio'/>\n";
    else if (opts.storageType == "virtio-scsi")
      xml << "      <target dev='sda' bus='scsi'/>\n";
    else // ahci-hd
      xml << "      <target dev='sda' bus='sata'/>\n";

    xml << "    </disk>\n";
  }

  // Network — use shared bridge if configured, otherwise default bridge0
  {
    auto bridge = opts.sharedBridge.empty() ? "bridge0" : opts.sharedBridge;
    xml << "    <interface type='bridge'>\n"
        << "      <source bridge='" << bridge << "'/>\n";
    if (opts.network.type == "e1000")
      xml << "      <model type='e1000'/>\n";
    else
      xml << "      <model type='virtio'/>\n";
    xml << "    </interface>\n";
  }

  // Display
  if (opts.display.mode == "vnc") {
    xml << "    <graphics type='vnc'";
    if (opts.display.port > 0)
      xml << " port='" << opts.display.port << "'";
    else
      xml << " port='-1' autoport='yes'";
    xml << " listen='0.0.0.0'/>\n";
  }

  // VirtIO RNG
  if (opts.virtioRng) {
    xml << "    <rng model='virtio'>\n"
        << "      <backend model='random'>/dev/random</backend>\n"
        << "    </rng>\n";
  }

  // Memory balloon
  if (opts.memoryBalloon) {
    xml << "    <memballoon model='virtio'/>\n";
  } else {
    xml << "    <memballoon model='none'/>\n";
  }

  // Shared volumes via virtio-9p (plan 9 filesystem) for jail<->VM sharing
  for (auto &vol : opts.sharedVolumes) {
    xml << "    <filesystem type='mount' accessmode='passthrough'>\n"
        << "      <source dir='" << vol.hostPath << "'/>\n"
        << "      <target dir='" << vol.tag << "'/>\n";
    if (vol.readOnly)
      xml << "      <readonly/>\n";
    xml << "    </filesystem>\n";
  }

  xml << "  </devices>\n"
      << "</domain>\n";

  return xml.str();
}

}
