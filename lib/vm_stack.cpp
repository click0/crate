// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// VM entries in stack orchestration: tap interface discovery and DNS registration.

#include "vm_stack.h"
#include "vm_run.h"
#include "err.h"
#include <rang.hpp>

#ifdef HAVE_LIBVIRT
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#endif

#include <fstream>
#include <string>

#define ERR(msg...) ERR2("vm_stack", msg)

// ---------------------------------------------------------------------------
// getVmTapInterface — parse libvirt XML to find tap device name
// ---------------------------------------------------------------------------

std::string getVmTapInterface(const std::string &vmName) {
#ifdef HAVE_LIBVIRT
  virConnectPtr conn = virConnectOpen("bhyve:///system");
  if (!conn)
    return "";

  virDomainPtr dom = virDomainLookupByName(conn, vmName.c_str());
  if (!dom) {
    virConnectClose(conn);
    return "";
  }

  char *xmlDesc = virDomainGetXMLDesc(dom, 0);
  virDomainFree(dom);
  virConnectClose(conn);

  if (!xmlDesc)
    return "";

  std::string xml(xmlDesc);
  ::free(xmlDesc);

  // Parse tap interface name from libvirt XML: <target dev='tapN'/>
  auto targetPos = xml.find("<target dev='tap");
  if (targetPos == std::string::npos)
    return "";

  auto devStart = xml.find("'", targetPos) + 1;
  auto devEnd = xml.find("'", devStart);
  if (devEnd == std::string::npos)
    return "";

  return xml.substr(devStart, devEnd - devStart);
#else
  (void)vmName;
  return "";
#endif
}

// ---------------------------------------------------------------------------
// registerVmInStack — connect VM to shared bridge and configure DNS
// ---------------------------------------------------------------------------

void registerVmInStack(const std::string &vmName,
                       const std::string &ip,
                       const std::string &bridgeIface) {
  // Connect the VM's tap interface to the shared bridge so it can
  // communicate with jails and other VMs on the same network.
  VmRun::connectToSharedBridge(vmName, bridgeIface);

  // Configure the VM to use the stack DNS service.
  // Use the bridge gateway (first usable IP) as DNS server.
  // Strip CIDR prefix if present in the ip string.
  std::string dnsIp = ip;
  auto slash = dnsIp.find('/');
  if (slash != std::string::npos)
    dnsIp = dnsIp.substr(0, slash);

  VmRun::configureVmDns(vmName, dnsIp);

  // Append to /etc/hosts so other stack members can resolve this VM by name.
  {
    std::ofstream ofs("/etc/hosts", std::ios::app);
    if (ofs)
      ofs << dnsIp << "\t" << vmName << "\n";
    else
      WARN("vm_stack: could not append VM '" << vmName
           << "' to /etc/hosts");
  }
}
