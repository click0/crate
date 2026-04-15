// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// VM lifecycle using libvirt bhyve driver.

#include "vm_run.h"
#include "ifconfig_ops.h"
#include "util.h"
#include "err.h"

#ifdef HAVE_LIBVIRT
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#endif

#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <iostream>
#include <fstream>
#include <sstream>

#define ERR(msg...) ERR2("vm", msg)

namespace VmRun {

// ---------------------------------------------------------------------------
// libvirt connection (singleton)
// ---------------------------------------------------------------------------

#ifdef HAVE_LIBVIRT

static virConnectPtr getConn() {
  static virConnectPtr conn = nullptr;
  if (!conn) {
    conn = virConnectOpen("bhyve:///system");
    if (!conn)
      return nullptr;
    static struct Cleanup {
      ~Cleanup() { if (conn) { virConnectClose(conn); conn = nullptr; } }
    } cleanup;
  }
  return conn;
}

#endif

bool available() {
#ifdef HAVE_LIBVIRT
  return getConn() != nullptr;
#else
  return false;
#endif
}

std::string createVm(const std::string &name, const VmSpec::VmOptions &opts) {
#ifdef HAVE_LIBVIRT
  auto *conn = getConn();
  if (!conn)
    ERR("libvirt connection not available")

  auto xml = VmSpec::generateDomainXml(name, opts);

  virDomainPtr dom = virDomainCreateXML(conn, xml.c_str(), 0);
  if (!dom) {
    virErrorPtr err = virGetLastError();
    ERR("failed to create VM: " << (err ? err->message : "unknown error"))
  }

  std::string domName = virDomainGetName(dom);
  virDomainFree(dom);
  return domName;
#else
  (void)name; (void)opts;
  ERR("VM support requires libvirt (compile with WITH_LIBVIRT)")
  return "";
#endif
}

void stopVm(const std::string &name, unsigned timeoutSec) {
#ifdef HAVE_LIBVIRT
  auto *conn = getConn();
  if (!conn) return;

  virDomainPtr dom = virDomainLookupByName(conn, name.c_str());
  if (!dom) return;

  // Try graceful shutdown first
  virDomainShutdown(dom);

  // Wait for shutdown
  for (unsigned i = 0; i < timeoutSec; i++) {
    virDomainInfo info;
    if (virDomainGetInfo(dom, &info) == 0 && info.state == VIR_DOMAIN_SHUTOFF)
      break;
    ::sleep(1);
  }

  // Force destroy if still running
  virDomainInfo info;
  if (virDomainGetInfo(dom, &info) == 0 && info.state != VIR_DOMAIN_SHUTOFF)
    virDomainDestroy(dom);

  virDomainFree(dom);
#else
  (void)name; (void)timeoutSec;
#endif
}

void destroyVm(const std::string &name) {
#ifdef HAVE_LIBVIRT
  auto *conn = getConn();
  if (!conn) return;

  virDomainPtr dom = virDomainLookupByName(conn, name.c_str());
  if (!dom) return;

  virDomainDestroy(dom);
  virDomainFree(dom);
#else
  (void)name;
#endif
}

std::vector<VmInfo> listVms() {
  std::vector<VmInfo> result;

#ifdef HAVE_LIBVIRT
  auto *conn = getConn();
  if (!conn) return result;

  virDomainPtr *doms = nullptr;
  int n = virConnectListAllDomains(conn, &doms,
    VIR_CONNECT_LIST_DOMAINS_ACTIVE | VIR_CONNECT_LIST_DOMAINS_INACTIVE);

  for (int i = 0; i < n; i++) {
    VmInfo info;
    info.name = virDomainGetName(doms[i]);

    virDomainInfo di;
    if (virDomainGetInfo(doms[i], &di) == 0) {
      info.vcpu = di.nrVirtCpu;
      info.memoryKiB = di.memory;
      switch (di.state) {
      case VIR_DOMAIN_RUNNING:  info.state = "running"; break;
      case VIR_DOMAIN_PAUSED:   info.state = "paused"; break;
      case VIR_DOMAIN_SHUTOFF:  info.state = "shutoff"; break;
      default:                  info.state = "unknown"; break;
      }
    }

    result.push_back(info);
    virDomainFree(doms[i]);
  }
  ::free(doms);
#endif

  return result;
}

VmInfo getVmInfo(const std::string &name) {
  VmInfo info;
  info.name = name;
  info.state = "unknown";

#ifdef HAVE_LIBVIRT
  auto *conn = getConn();
  if (!conn) return info;

  virDomainPtr dom = virDomainLookupByName(conn, name.c_str());
  if (!dom) return info;

  virDomainInfo di;
  if (virDomainGetInfo(dom, &di) == 0) {
    info.vcpu = di.nrVirtCpu;
    info.memoryKiB = di.memory;
    switch (di.state) {
    case VIR_DOMAIN_RUNNING:  info.state = "running"; break;
    case VIR_DOMAIN_PAUSED:   info.state = "paused"; break;
    case VIR_DOMAIN_SHUTOFF:  info.state = "shutoff"; break;
    default:                  info.state = "unknown"; break;
    }
  }

  virDomainFree(dom);
#endif

  return info;
}

void connectToSharedBridge(const std::string &vmName,
                           const std::string &bridgeIface) {
#ifdef HAVE_LIBVIRT
  auto *conn = getConn();
  if (!conn) return;

  virDomainPtr dom = virDomainLookupByName(conn, vmName.c_str());
  if (!dom) return;

  // Get the VM's tap interface name from libvirt XML
  char *xmlDesc = virDomainGetXMLDesc(dom, 0);
  virDomainFree(dom);
  if (!xmlDesc) return;

  std::string xml(xmlDesc);
  ::free(xmlDesc);

  // Parse tap interface name from XML: <target dev='tap0'/>
  auto targetPos = xml.find("<target dev='tap");
  if (targetPos != std::string::npos) {
    auto devStart = xml.find("'", targetPos) + 1;
    auto devEnd = xml.find("'", devStart);
    auto tapIface = xml.substr(devStart, devEnd - devStart);

    // Add tap to the shared bridge
    if (Util::interfaceExists(tapIface) && Util::interfaceExists(bridgeIface)) {
      IfconfigOps::bridgeAddMember(bridgeIface, tapIface);
    }
  }
#else
  (void)vmName; (void)bridgeIface;
#endif
}

void configureVmDns(const std::string &vmName, const std::string &dnsIp) {
  // Create a shared directory with resolv.conf for the VM
  std::string dnsShareDir = "/var/run/crate/vm/" + vmName + "/dns";

  // Create the directory tree
  ::mkdir("/var/run/crate", 0755);
  ::mkdir("/var/run/crate/vm", 0755);
  ::mkdir(("/var/run/crate/vm/" + vmName).c_str(), 0755);
  ::mkdir(dnsShareDir.c_str(), 0755);

  // Write resolv.conf with the stack DNS IP
  std::string resolvPath = dnsShareDir + "/resolv.conf";
  {
    std::ofstream ofs(resolvPath);
    if (!ofs) {
      WARN("vm: could not write DNS resolv.conf for VM '" << vmName
           << "' at " << resolvPath);
      return;
    }
    ofs << "# Generated by crate for stack DNS\n"
        << "nameserver " << dnsIp << "\n";
  }

#ifdef HAVE_LIBVIRT
  // Attempt to add as a virtio-9p mount if the VM supports shared_volumes.
  // This mounts the directory containing resolv.conf into the guest so it
  // can copy or bind-mount /dns/resolv.conf -> /etc/resolv.conf.
  auto *conn = getConn();
  if (!conn) {
    WARN("vm: DNS configured on host but libvirt unavailable; "
         "guest must be configured manually for VM '" << vmName << "'");
    return;
  }

  virDomainPtr dom = virDomainLookupByName(conn, vmName.c_str());
  if (!dom) {
    WARN("vm: DNS configured on host but VM '" << vmName
         << "' not found; guest DNS must be configured manually");
    return;
  }

  // Check if the VM already has filesystem devices (shared_volumes support)
  char *xmlDesc = virDomainGetXMLDesc(dom, 0);
  virDomainFree(dom);
  if (xmlDesc) {
    std::string xml(xmlDesc);
    ::free(xmlDesc);

    if (xml.find("<filesystem") != std::string::npos) {
      // VM has shared_volumes support — attach DNS share via 9p.
      // The guest should mount: mount -t 9p dns_share /mnt/dns
      std::string fsXml =
        "<filesystem type='mount' accessmode='passthrough'>\n"
        "  <source dir='" + dnsShareDir + "'/>\n"
        "  <target dir='dns_share'/>\n"
        "  <readonly/>\n"
        "</filesystem>\n";

      virDomainPtr dom2 = virDomainLookupByName(conn, vmName.c_str());
      if (dom2) {
        if (virDomainAttachDevice(dom2, fsXml.c_str()) < 0) {
          WARN("vm: could not hot-attach DNS 9p share for VM '" << vmName
               << "'; guest DNS must be configured manually");
        }
        virDomainFree(dom2);
      }
    } else {
      WARN("vm: VM '" << vmName << "' has no shared_volumes support; "
           "DNS resolv.conf written to " << resolvPath
           << " but cannot be auto-mounted in guest");
    }
  }
#else
  (void)vmName;
  WARN("vm: DNS resolv.conf written to " << resolvPath
       << " but VM support requires libvirt for auto-configuration");
#endif
}

std::string generateCloudInitFor9p(
    const std::vector<VmSpec::VirtioFsMount> &volumes) {
  if (volumes.empty())
    return "";

  // Generate cloud-init user-data that mounts each 9p share in the guest.
  // This script runs on first boot and creates mount points + fstab entries.
  std::ostringstream ud;
  ud << "#cloud-config\n"
     << "# Generated by crate — mount virtio-9p shared volumes\n"
     << "bootcmd:\n";

  for (auto &vol : volumes) {
    // Derive a mount point from the tag name
    std::string mountPoint = "/mnt/" + vol.tag;

    ud << "  - mkdir -p " << mountPoint << "\n"
       << "  - mount -t 9p -o trans=virtio";
    if (vol.readOnly)
      ud << ",ro";
    ud << " " << vol.tag << " " << mountPoint << "\n";
  }

  // Also write fstab entries so mounts persist across reboots
  ud << "write_files:\n"
     << "  - path: /etc/fstab\n"
     << "    append: true\n"
     << "    content: |\n";

  for (auto &vol : volumes) {
    std::string mountPoint = "/mnt/" + vol.tag;
    std::string opts = "trans=virtio,nofail";
    if (vol.readOnly)
      opts += ",ro";
    ud << "      " << vol.tag << " " << mountPoint
       << " 9p " << opts << " 0 0\n";
  }

  // Write to a temp file under /var/run/crate
  ::mkdir("/var/run/crate", 0755);
  ::mkdir("/var/run/crate/cloud-init", 0755);

  // Use a unique name based on PID to avoid collisions
  std::string path = "/var/run/crate/cloud-init/user-data-9p-"
                     + std::to_string(::getpid()) + ".yaml";

  std::ofstream ofs(path);
  if (!ofs) {
    WARN("vm: could not write cloud-init user-data to " << path);
    return "";
  }
  ofs << ud.str();

  return path;
}

}
