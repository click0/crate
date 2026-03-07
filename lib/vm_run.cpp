// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// VM lifecycle using libvirt bhyve driver.

#include "vm_run.h"
#include "err.h"

#ifdef HAVE_LIBVIRT
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#endif

#include <unistd.h>
#include <string.h>

#include <iostream>

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

}
