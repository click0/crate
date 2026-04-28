// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure validation/warning logic extracted from lib/validate.cpp so it
// can be unit-tested. The CLI command (validateCrateSpec) handles
// parsing, calling spec.validate(), and printing — those bits stay
// in validate.cpp. Everything that examines a Spec object and produces
// human-readable warnings lives here.

#pragma once

#include <string>
#include <vector>

class Spec;

namespace ValidatePure {

// Walk the spec and return one string per warning condition triggered.
// Pure: does not print, does not throw, does not call into Config.
std::vector<std::string> gatherWarnings(const Spec &spec);

}
