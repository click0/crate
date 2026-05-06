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

  // Gather warnings (pure logic in lib/validate_pure.cpp).
  auto warnings = ValidatePure::gatherWarnings(spec);

  // Strict mode (0.7.16): also gather structural errors and treat
  // both warnings and structural errors as fatal. Without --strict,
  // warnings just print and the command exits 0.
  std::vector<std::string> strictErrors;
  if (args.validateStrict)
    strictErrors = ValidatePure::gatherStrictErrors(spec);

  for (auto &msg : warnings) {
    auto color = args.validateStrict ? rang::fg::red : rang::fg::yellow;
    auto label = args.validateStrict ? "ERROR (strict)" : "WARNING";
    std::cerr << color << label << ": " << msg << rang::style::reset << std::endl;
  }
  for (auto &msg : strictErrors)
    std::cerr << rang::fg::red << "ERROR (strict): " << msg << rang::style::reset << std::endl;

  // Decide pass/fail. In strict mode any warning OR strict error is
  // fatal; non-strict only fails on schema errors (which already
  // threw above).
  bool failed = args.validateStrict
                  && (!warnings.empty() || !strictErrors.empty());
  if (failed) {
    std::cerr << rang::fg::red
              << "Spec '" << args.validateSpec << "' failed --strict validation: "
              << warnings.size() << " warning"
              << (warnings.size() == 1 ? "" : "s")
              << ", " << strictErrors.size() << " structural error"
              << (strictErrors.size() == 1 ? "" : "s")
              << rang::style::reset << std::endl;
    return false;
  }

  std::cout << rang::fg::green << "Spec '" << args.validateSpec << "' is valid";
  if (!warnings.empty())
    std::cout << " (" << warnings.size() << " warning"
              << (warnings.size() > 1 ? "s" : "") << ")";
  if (args.validateStrict)
    std::cout << " [--strict]";
  std::cout << rang::style::reset << std::endl;

  return true;
}
