// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// `crate inspect TARGET` — gather a JSON snapshot of a running
// container's runtime state and write it to stdout. Pure formatting
// + escape handling lives in lib/inspect_pure.cpp; this file is the
// I/O glue (libjail, sysctl, rctl(8), mount(8), ZFS).
//

#include "args.h"
#include "commands.h"
#include "inspect_pure.h"
#include "ctx.h"
#include "gui_registry.h"
#include "jail_query.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <ctime>
#include <iostream>
#include <string>

#define ERR(msg...) ERR2("inspect", msg)

namespace {

std::optional<JailQuery::JailInfo> resolve(const std::string &t) {
  auto j = JailQuery::getJailByName(t);
  if (j) return j;
  try {
    int id = std::stoi(t);
    return JailQuery::getJailByJid(id);
  } catch (...) { return std::nullopt; }
}

// Pull a curated set of jail params that are interesting for a
// snapshot. The full list is huge and noisy; this set covers the
// security-relevant + name-mapping fields most operators care about.
const std::vector<std::string> &interestingJailParams() {
  static const std::vector<std::string> v = {
    "name", "host.hostname", "host.domainname", "path", "ip4", "ip6",
    "securelevel", "enforce_statfs",
    "allow.chflags", "allow.mount", "allow.mount.devfs",
    "allow.mount.fdescfs", "allow.mount.nullfs", "allow.mount.tmpfs",
    "allow.mount.zfs", "allow.mlock", "allow.nfsd", "allow.raw_sockets",
    "allow.reserved_ports", "allow.set_hostname", "allow.socket_af",
    "allow.suser", "allow.sysvipc",
    "vnet", "vnet.interface",
    "persist", "dying", "osreldate", "osrelease",
  };
  return v;
}

void collectInterfaces(const JailQuery::JailInfo &jail,
                       InspectPure::InspectData &data) {
  // We expose only the primary IPv4 from JailQuery — full per-iface
  // enumeration would need libifconfig integration, and is left to a
  // future release.
  if (!jail.ip4.empty()) {
    InspectPure::Interface i;
    i.name = "primary";
    i.ip4 = jail.ip4;
    data.interfaces.push_back(i);
  }
}

} // anon

bool inspectCrate(const Args &args) {
  if (args.inspectTarget.empty())
    ERR("inspect command requires a container name or JID")

  auto jail = resolve(args.inspectTarget);
  if (!jail)
    ERR("container '" << args.inspectTarget << "' not found or not running")

  InspectPure::InspectData data;
  data.name      = jail->name;
  data.jid       = jail->jid;
  data.hostname  = jail->hostname;
  data.path      = jail->path;
  try { data.osrelease = Util::getSysctlString("kern.osrelease"); } catch (...) {}

  // Curated jail params via libjail.
  for (auto &p : interestingJailParams()) {
    auto v = JailQuery::getJailParam(jail->jid, p);
    if (!v.empty())
      data.jailParams[p] = v;
  }

  collectInterfaces(*jail, data);

  // RCTL usage.
  try {
    auto rctlOut = Util::execCommandGetOutput(
      {CRATE_PATH_RCTL, "-u", "jail:" + std::to_string(jail->jid)},
      "query RCTL usage");
    InspectPure::applyRctlOutput(rctlOut, data);
  } catch (...) {}

  // Mounts visible from host /sbin/mount -p (path-format) — filter to
  // entries inside the jail rootfs.
  try {
    auto mountOut = Util::execCommandGetOutput(
      {"/sbin/mount"}, "list mounts");
    InspectPure::applyMountOutput(mountOut, jail->path, data);
  } catch (...) {}

  // ZFS dataset (best-effort — empty if path isn't on ZFS).
  try {
    if (Util::Fs::isOnZfs(jail->path)) {
      data.zfsDataset = Util::Fs::getZfsDataset(jail->path);
      try {
        auto origin = Util::execCommandGetOutput(
          {"/sbin/zfs", "get", "-H", "-o", "value", "origin", data.zfsDataset},
          "query ZFS origin");
        // Strip trailing newline.
        while (!origin.empty() && (origin.back() == '\n' || origin.back() == '\r'))
          origin.pop_back();
        if (origin != "-") data.zfsOrigin = origin;
      } catch (...) {}
    }
  } catch (...) {}

  // Process count via ps -J.
  try {
    auto psOut = Util::execCommandGetOutput(
      {"/bin/ps", "-J", std::to_string(jail->jid), "-o", "pid="},
      "count jail processes");
    unsigned n = 0;
    for (char c : psOut) if (c == '\n') n++;
    data.processCount = n;
  } catch (...) {}

  // GUI session (if any).
  try {
    auto reg = Ctx::GuiRegistry::lock();
    auto *e = reg->findByTarget(jail->name);
    if (e) {
      data.hasGui     = true;
      data.guiDisplay = e->displayNum;
      data.guiVncPort = e->vncPort;
      data.guiWsPort  = e->wsPort;
      data.guiMode    = e->mode;
    }
    reg->unlock();
  } catch (...) {}

  data.inspectedAt = ::time(nullptr);
  // started_at is harder — not exposed by libjail; left at 0 for now.

  std::cout << InspectPure::renderJson(data);
  return true;
}
