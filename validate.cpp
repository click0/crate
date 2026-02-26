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

  // Report
  std::cout << rang::fg::green << "Spec '" << args.validateSpec << "' is valid";
  if (warnings > 0)
    std::cout << " (" << warnings << " warning" << (warnings > 1 ? "s" : "") << ")";
  std::cout << rang::style::reset << std::endl;

  return true;
}
