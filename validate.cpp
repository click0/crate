// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include "args.h"
#include "spec.h"
#include "err.h"

#include <rang.hpp>

#include <iostream>

#define ERR(msg...) \
  ERR2("validate", msg)

bool validateCrateSpec(const Args &args) {
  if (args.validateSpec.empty())
    ERR("spec file required")

  unsigned warnings = 0;
  auto warn = [&warnings](const std::string &msg) {
    std::cerr << rang::fg::yellow << "WARNING: " << msg << rang::style::reset << std::endl;
    warnings++;
  };

  // Parse the spec — throws on syntax errors
  auto spec = parseSpec(args.validateSpec);

  // Run standard validation — throws on errors
  spec.validate();

  // Additional cross-checks and warnings
  if (spec.allowSysvipc)
    warn("ipc/sysvipc=true reduces isolation; only enable if the application requires System V shared memory");

  if (spec.optionExists("net") && spec.optionExists("tor")) {
    auto optNet = spec.optionNet();
    if (optNet && optNet->outboundLan)
      warn("net/outbound includes LAN with tor enabled — traffic may bypass Tor");
  }

  if (!spec.limits.empty() && spec.limits.find("maxproc") == spec.limits.end())
    warn("limits section present but maxproc not set — consider setting a process limit");

  // Encryption cross-checks (§1)
  if (spec.encrypted)
    warn("encrypted=true requires ZFS dataset with encryption enabled on the jail directory");

  // DNS filter cross-checks (§4)
  if (spec.dnsFilter) {
    if (spec.dnsFilter->block.empty() && spec.dnsFilter->allow.empty())
      warn("dns_filter section present but no allow/block rules defined");
    if (!spec.optionExists("net"))
      warn("dns_filter requires networking (option 'net') to be useful");
  }

  // Security cross-checks (§8)
  if (spec.allowChflags)
    warn("security/allow_chflags=true lets jail processes change file flags — reduces host protection");

  if (spec.allowMlock)
    warn("security/allow_mlock=true lets jail processes lock memory — may affect host performance");

  // COW cross-checks (§6)
  if (spec.cowOptions) {
    if (spec.cowOptions->backend == "zfs")
      warn("cow/backend=zfs requires jail directory to be on a ZFS dataset");
    if (spec.cowOptions->mode == "persistent")
      warn("cow/mode=persistent will accumulate clone datasets over time; clean up manually");
  }

  // X11 nested mode cross-checks (§11)
  if (spec.x11Options) {
    if (spec.x11Options->mode == "nested")
      warn("x11/mode=nested requires Xephyr to be installed on the host");
  }

  // Clipboard cross-checks (§12)
  if (spec.clipboardOptions) {
    if (spec.clipboardOptions->mode == "isolated" &&
        (!spec.x11Options || spec.x11Options->mode != "nested"))
      warn("clipboard/mode=isolated only provides full isolation with x11/mode=nested");
  }

  // D-Bus cross-checks (§13)
  if (spec.dbusOptions) {
    if (spec.dbusOptions->sessionBus)
      warn("dbus/session=true requires dbus-daemon to be installed in the container");
  }

  // Socket proxy cross-checks (§15)
  if (spec.socketProxy) {
    if (spec.socketProxy->share.empty() && spec.socketProxy->proxy.empty())
      warn("socket_proxy section present but no share/proxy entries defined");
  }

  // Firewall policy cross-checks (§3)
  if (spec.firewallPolicy) {
    if (!spec.optionExists("net"))
      warn("firewall policy requires 'net' option to be enabled");
    if (spec.firewallPolicy->defaultPolicy == "block" &&
        spec.firewallPolicy->allowTcp.empty() && spec.firewallPolicy->allowUdp.empty())
      warn("firewall default=block with no allow rules — all outbound traffic will be blocked");
  }

  // Capsicum/MAC cross-checks (§8)
  if (spec.securityAdvanced) {
    if (spec.securityAdvanced->capsicum)
      warn("capsicum mode is very restrictive — only pre-opened file descriptors will be usable");
    if (!spec.securityAdvanced->macRules.empty())
      warn("mac_bsdextended rules require the mac_bsdextended kernel module to be loaded");
  }

  // Terminal cross-checks (§16)
  if (spec.terminalOptions) {
    if (spec.terminalOptions->devfsRuleset >= 0)
      warn("custom devfs_ruleset may affect device visibility inside the jail");
  }

  // Report
  std::cout << rang::fg::green << "Spec '" << args.validateSpec << "' is valid";
  if (warnings > 0)
    std::cout << " (" << warnings << " warning" << (warnings > 1 ? "s" : "") << ")";
  std::cout << rang::style::reset << std::endl;

  return true;
}
