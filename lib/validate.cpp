// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "spec.h"
#include "validate_pure.h"
#include "err.h"

#include <rang.hpp>

#include <iostream>

#define ERR(msg...) \
  ERR2("validate", msg)

bool validateCrateSpec(const Args &args) {
  if (args.validateSpec.empty())
    ERR("spec file required")

  // Parse the spec — throws on syntax errors
  auto spec = parseSpec(args.validateSpec);

  // Run standard validation — throws on errors
  spec.validate();

  // Gather and print warnings (pure logic in lib/validate_pure.cpp)
  auto warnings = ValidatePure::gatherWarnings(spec);
  for (auto &msg : warnings)
    std::cerr << rang::fg::yellow << "WARNING: " << msg << rang::style::reset << std::endl;

  std::cout << rang::fg::green << "Spec '" << args.validateSpec << "' is valid";
  if (!warnings.empty())
    std::cout << " (" << warnings.size() << " warning"
              << (warnings.size() > 1 ? "s" : "") << ")";
  std::cout << rang::style::reset << std::endl;

  return true;
}
