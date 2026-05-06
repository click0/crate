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

// Strict-mode (0.7.16) checks that go beyond the regular validate +
// warnings: structural inconsistencies that are accepted today but
// almost certainly indicate a typo or copy-paste error in the spec.
// Same shape as gatherWarnings — one human-readable error per
// violation. The CLI promotes these to fatal in `--strict` mode.
//
// Catalogue (v1):
//   - duplicate inbound TCP/UDP host ports
//   - duplicate share destinations (two different host paths
//     mapping to the same jail-side path)
//   - empty mount source or destination
//   - x11/mode=shared in --strict (regular validate just warns)
//   - unbounded RCTL — `limits:` section absent OR has no
//     memoryuse/maxproc cap
//
// Pure: same constraints as gatherWarnings.
std::vector<std::string> gatherStrictErrors(const Spec &spec);

}
