// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "validate_pure.h"
#include "spec.h"

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
                  "read host keystrokes and manipulate windows; prefer mode=nested or "
                  "mode=headless for security-sensitive workloads");
  } else {
    // No x11Options block at all: when GUI is implied, default mode is "shared".
    // Only warn when the spec actually pulls in something that triggers GUI.
    if (spec.optionExists("x11"))
      w.push_back("x11 option without an explicit x11/mode defaults to 'shared', which "
                  "provides NO display isolation; set x11/mode=nested or mode=headless "
                  "for security-sensitive workloads");
  }

  if (spec.clipboardOptions) {
    if (spec.clipboardOptions->mode == "isolated" &&
        (!spec.x11Options || spec.x11Options->mode != "nested"))
      w.push_back("clipboard/mode=isolated only provides full isolation with x11/mode=nested");
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
  // since they collide in the jail filesystem.
  {
    std::unordered_map<std::string, std::string> dst2src;
    auto check = [&](const char *kind,
                     const std::vector<std::pair<std::string, std::string>> &v) {
      for (const auto &[host, jail] : v) {
        auto it = dst2src.find(jail);
        if (it != dst2src.end() && it->second != host) {
          std::ostringstream o;
          o << kind << " destination '" << jail
            << "' is mapped from two different host sources: '"
            << it->second << "' and '" << host << "'";
          e.push_back(o.str());
        } else {
          dst2src[jail] = host;
        }
      }
    };
    check("share/dir",  spec.dirsShare);
    check("share/file", spec.filesShare);
  }

  // --- Empty mount source/destination ---
  // Caught at run time today as a confusing error; --strict wants
  // it surfaced at validate time.
  for (const auto &[host, jail] : spec.dirsShare) {
    if (host.empty() || jail.empty())
      e.push_back("share/dir: empty source or destination ("
                  "host='" + host + "', jail='" + jail + "')");
  }
  for (const auto &[host, jail] : spec.filesShare) {
    if (host.empty() || jail.empty())
      e.push_back("share/file: empty source or destination ("
                  "host='" + host + "', jail='" + jail + "')");
  }

  // --- x11/mode=shared promoted to error in strict mode ---
  if (spec.x11Options && spec.x11Options->mode == "shared") {
    e.push_back("x11/mode=shared is rejected in --strict mode "
                "(no display isolation; switch to mode=nested or mode=headless, "
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
