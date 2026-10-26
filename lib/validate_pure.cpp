// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "validate_pure.h"
#include "spec.h"
#include "mounts_pure.h"   // 1.1.63

#include <cctype>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>

namespace ValidatePure {

std::vector<std::string> gatherWarnings(const Spec &spec) {
  std::vector<std::string> w;

  if (spec.allowSysvipc)
    w.push_back("ipc/sysvipc=true reduces isolation; only enable if the application requires System V shared memory");

  // 1.1.58: thin jail — the userland is the host's, mounted read-only, so
  // base trimming never runs (base/keep is harmless; base/remove is the
  // one that signals a misunderstanding).
  if (spec.baseHostRo && !spec.baseRemove.empty())
    w.push_back("base/mode=host-ro — base/remove has no effect: the host userland is mounted read-only and never trimmed");

  if (spec.optionExists("net") && spec.optionExists("tor")) {
    auto optNet = spec.optionNet();
    if (optNet && optNet->outboundLan)
      w.push_back("net/outbound includes LAN with tor enabled — traffic may bypass Tor");
  }

  // IPv6 cross-checks
  if (spec.optionExists("net")) {
    auto optNet = spec.optionNet();
    if (optNet && optNet->ipv6) {
      if (!optNet->allowOutbound())
        w.push_back("net/ipv6=true but no outbound traffic allowed — IPv6 will have no effect");
      if (spec.optionExists("tor"))
        w.push_back("net/ipv6=true with tor — Tor does not support IPv6 outbound by default");
    }
  }

  if (!spec.limits.empty() && spec.limits.find("maxproc") == spec.limits.end())
    w.push_back("limits section present but maxproc not set — consider setting a process limit");

  if (spec.encrypted)
    w.push_back("encrypted=true requires ZFS dataset with encryption enabled on the jail directory");

  if (spec.dnsFilter) {
    if (spec.dnsFilter->block.empty() && spec.dnsFilter->allow.empty())
      w.push_back("dns_filter section present but no allow/block rules defined");
    if (!spec.optionExists("net"))
      w.push_back("dns_filter requires networking (option 'net') to be useful");
  }

  if (spec.allowChflags)
    w.push_back("security/allow_chflags=true lets jail processes change file flags — reduces host protection");

  if (spec.allowMlock)
    w.push_back("security/allow_mlock=true lets jail processes lock memory — may affect host performance");

  if (spec.securelevel >= 0 && spec.securelevel < 2)
    w.push_back("security/securelevel=" + std::to_string(spec.securelevel) + " is less restrictive than bastille's default (2)");

  if (spec.childrenMax > 0)
    w.push_back("security/children_max=" + std::to_string(spec.childrenMax) + " allows nested jails — ensure this is intended");

  if (!spec.cpuset.empty()) {
    for (char c : spec.cpuset) {
      if (!::isdigit(c) && c != ',' && c != '-') {
        w.push_back("security/cpuset contains invalid character '" + std::string(1, c) + "'");
        break;
      }
    }
  }

  if (spec.cowOptions) {
    if (spec.cowOptions->backend == "zfs")
      w.push_back("cow/backend=zfs requires jail directory to be on a ZFS dataset");
    if (spec.cowOptions->mode == "persistent")
      w.push_back("cow/mode=persistent will accumulate clone datasets over time; clean up manually");
  }

  if (spec.x11Options) {
    if (spec.x11Options->mode == "nested")
      w.push_back("x11/mode=nested requires Xephyr to be installed on the host");
    if (spec.x11Options->mode == "shared")
      w.push_back("x11/mode=shared provides NO display isolation — jail processes can "
                  "read host keystrokes and manipulate windows; prefer x11/mode=nested or "
                  "gui/mode=headless for security-sensitive workloads");
  } else {
    // No x11Options block at all: when GUI is implied, default mode is "shared".
    // Only warn when the spec actually pulls in something that triggers GUI.
    if (spec.optionExists("x11"))
      w.push_back("x11 option without an explicit x11/mode defaults to 'shared', which "
                  "provides NO display isolation; set x11/mode=nested or gui/mode=headless "
                  "for security-sensitive workloads");
  }

  if (spec.clipboardOptions) {
    if (spec.clipboardOptions->mode == "isolated" &&
        (!spec.x11Options || spec.x11Options->mode != "nested"))
      w.push_back("clipboard/mode=isolated only provides full isolation with x11/mode=nested");
  }

  // 0.8.46: gui/resolution is ignored when the resolved mode is
  // shared/wayland — the host compositor decides resolution per
  // wl_output, the operator's spec value has no effect. Warn so
  // operators don't think they're configuring the jail's display.
  if (spec.guiOptions
      && spec.guiOptions->resolution != "1280x720"   // default
      && (spec.guiOptions->mode == "wayland"
          || spec.guiOptions->mode == "auto")) {   // 1.1.46: "shared" is not a gui/mode
    w.push_back("gui/resolution is ignored when gui/mode resolves to shared "
                "or wayland (the host compositor decides resolution via "
                "wl_output / X11 root window size); only honoured for "
                "mode=nested (Xephyr) and gui/mode=headless (Xvfb)");
  }

  if (spec.dbusOptions) {
    if (spec.dbusOptions->sessionBus)
      w.push_back("dbus/session=true requires dbus-daemon to be installed in the container");
  }

  if (spec.socketProxy) {
    if (spec.socketProxy->share.empty() && spec.socketProxy->proxy.empty())
      w.push_back("socket_proxy section present but no share/proxy entries defined");
  }

  if (spec.firewallPolicy) {
    if (!spec.optionExists("net"))
      w.push_back("firewall policy requires 'net' option to be enabled");
    if (spec.firewallPolicy->defaultPolicy == "block" &&
        spec.firewallPolicy->allowTcp.empty() && spec.firewallPolicy->allowUdp.empty())
      w.push_back("firewall default=block with no allow rules — all outbound traffic will be blocked");
  }

  if (spec.securityAdvanced) {
    if (spec.securityAdvanced->capsicum)
      w.push_back("capsicum mode is very restrictive — only pre-opened file descriptors will be usable");
    if (!spec.securityAdvanced->macRules.empty())
      w.push_back("mac_bsdextended rules require the mac_bsdextended kernel module to be loaded");
  }

  if (spec.terminalOptions) {
    if (spec.terminalOptions->devfsRuleset >= 0)
      w.push_back("custom devfs_ruleset may affect device visibility inside the jail");
  }

  // 1.1.62: device classes that are a real privilege grant
  for (const auto &dw : DevicesPure::warnings(spec.devices))
    w.push_back(dw);

  // 1.1.63: shares and tmpfs
  for (const auto &s : spec.dirsShare)
    if (!s.readOnly && (s.host == "$HOME" || s.host == "/" || s.host == "/home" || s.host == "/usr/home"))
      w.push_back("dirs/share: '" + s.host + "' is shared read-write as a whole; consider ':ro' or a subdirectory");
  for (const auto &t : spec.tmpfs)
    for (const auto &s : spec.dirsShare)
      if (MountsPure::isUnder(s.jail, t.path) && s.jail != t.path)
        w.push_back("tmpfs at '" + t.path + "' is mounted after the share at '" + s.jail + "' and hides it");
  if (!spec.etcKeep.empty() && !spec.baseHostRo)
    w.push_back("etc/keep copies host /etc entries at create time; the jail's /etc is a full copy from base.txz here, so only the named entries are replaced");

  // 1.1.64: run/user
  if (spec.runUser == "root") {
    w.push_back("run/user: root — the command runs as root inside the jail; drop it unless the program needs it (the default is the operator's own account)");
  } else if (!spec.runUser.empty()) {
    bool homeShare = false;
    for (const auto &s : spec.dirsShare)
      if (s.host.compare(0, 5, "$HOME") == 0 || s.jail.compare(0, 5, "$HOME") == 0) homeShare = true;
    for (const auto &s : spec.filesShare)
      if (s.host.compare(0, 5, "$HOME") == 0 || s.jail.compare(0, 5, "$HOME") == 0) homeShare = true;
    if (homeShare)
      w.push_back("run/user: " + spec.runUser + " — shares under $HOME belong to the operator's uid; '" + spec.runUser + "' can read but not write them unless the host directories allow it");
    if (spec.x11Options || spec.guiOptions || spec.optionExists("x11"))
      w.push_back("run/user: " + spec.runUser + " — the X11 authority is copied for the operator's account; a GUI program running as '" + spec.runUser + "' may not reach the display");
  }

  // 1.1.67: privacy — an anonymity network with the host's identity
  if ((spec.optionExists("tor") || spec.optionExists("i2pd")) && spec.privacyHostid.empty())
    w.push_back("options: tor/i2pd without privacy/hostid — the jail carries the host's kern.hostuuid/kern.hostid; add `privacy: {hostid: random, hostname: random}` so programs inside cannot identify the machine");

  // 1.1.65: run/timeout
  if (spec.runTimeoutSec > 0) {
    if (spec.runCmdExecutable.empty())
      w.push_back("run/timeout: " + std::to_string(spec.runTimeoutSec) + "s on a service-only crate — the container itself is stopped after that long (the services get `service stop`), which is rarely what a daemon wants");
    if (spec.healthcheck && spec.healthcheck->startPeriodSec >= spec.runTimeoutSec)
      w.push_back("run/timeout: " + std::to_string(spec.runTimeoutSec) + "s is not longer than healthcheck/start_period; the command would be killed before the first probe");
  }

  return w;
}

namespace {

// Format a port-range as "8080" or "8080-8090" for error messages.
std::string fmtRange(unsigned a, unsigned b) {
  if (a == b) return std::to_string(a);
  std::ostringstream o;
  o << a << "-" << b;
  return o.str();
}

// Detect overlap between two ports/ranges. Inclusive bounds.
bool rangesOverlap(unsigned a1, unsigned a2, unsigned b1, unsigned b2) {
  return !(a2 < b1 || b2 < a1);
}

// Append a "duplicate inbound port" error for one protocol's list.
// Quadratic in #rules; spec author has typically <20 rules total
// so it's fine. Ranges are checked for overlap, not just exact dup.
void checkInboundPortConflicts(
    const char *proto,
    const std::vector<std::pair<Spec::NetOptDetails::PortRange,
                                Spec::NetOptDetails::PortRange>> &rules,
    std::vector<std::string> &out) {
  for (size_t i = 0; i < rules.size(); i++) {
    const auto &host_i = rules[i].first;
    for (size_t j = i + 1; j < rules.size(); j++) {
      const auto &host_j = rules[j].first;
      if (rangesOverlap(host_i.first, host_i.second,
                        host_j.first, host_j.second)) {
        std::ostringstream o;
        o << "net/inbound/" << proto
          << ": host port " << fmtRange(host_i.first, host_i.second)
          << " conflicts with " << fmtRange(host_j.first, host_j.second)
          << " (rules " << (i + 1) << " and " << (j + 1) << ")";
        out.push_back(o.str());
      }
    }
  }
}

} // anon

std::vector<std::string> gatherStrictErrors(const Spec &spec) {
  std::vector<std::string> e;

  // --- Inbound port conflicts ---
  if (spec.optionExists("net")) {
    auto optNet = spec.optionNet();
    if (optNet) {
      checkInboundPortConflicts("tcp", optNet->inboundPortsTcp, e);
      checkInboundPortConflicts("udp", optNet->inboundPortsUdp, e);
    }
  }

  // --- Duplicate share destinations ---
  // Two different host paths mapping to the same jail-side path is
  // ambiguous: which one wins? Almost always a copy-paste error.
  // Same destination across dirsShare and filesShare is also flagged
  // since they collide in the jail filesystem. (1.1.63: keyed by the
  // jail-side path; the pair's halves were read the wrong way round
  // before, so one host directory shared under two jail paths was
  // flagged and two hosts behind one jail path were not.)
  {
    std::unordered_map<std::string, std::string> dst2src;
    auto check = [&](const char *kind, const std::vector<Spec::Share> &v) {
      for (const auto &s : v) {
        auto it = dst2src.find(s.jail);
        if (it != dst2src.end() && it->second != s.host) {
          std::ostringstream o;
          o << kind << " destination '" << s.jail
            << "' is mapped from two different host sources: '"
            << it->second << "' and '" << s.host << "'";
          e.push_back(o.str());
        } else {
          dst2src[s.jail] = s.host;
        }
      }
    };
    check("share/dir",  spec.dirsShare);
    check("share/file", spec.filesShare);
  }

  // --- Empty mount source/destination ---
  // Caught at run time today as a confusing error; --strict wants
  // it surfaced at validate time.
  for (const auto &s : spec.dirsShare) {
    if (s.host.empty() || s.jail.empty())
      e.push_back("share/dir: empty source or destination ("
                  "host='" + s.host + "', jail='" + s.jail + "')");
  }
  for (const auto &s : spec.filesShare) {
    if (s.host.empty() || s.jail.empty())
      e.push_back("share/file: empty source or destination ("
                  "host='" + s.host + "', jail='" + s.jail + "')");
  }

  // --- x11/mode=shared promoted to error in strict mode ---
  if (spec.x11Options && spec.x11Options->mode == "shared") {
    e.push_back("x11/mode=shared is rejected in --strict mode "
                "(no display isolation; switch to x11/mode=nested or gui/mode=headless, "
                "or drop --strict if intentional)");
  } else if (!spec.x11Options && spec.optionExists("x11")) {
    e.push_back("x11 option without explicit x11/mode is rejected in --strict mode "
                "(implicit default is 'shared', which has no display isolation)");
  }

  // --- Unbounded RCTL ---
  // Strict mode wants at least one of memoryuse/maxproc set so a
  // runaway process inside the jail can't OOM-kill the host.
  if (spec.limits.empty()
      || (spec.limits.find("memoryuse") == spec.limits.end()
          && spec.limits.find("maxproc") == spec.limits.end())) {
    e.push_back("limits: --strict requires at least 'memoryuse' or 'maxproc' "
                "to bound the jail; runaway processes can otherwise OOM-kill the host");
  }

  return e;
}

}
