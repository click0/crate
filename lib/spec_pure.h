// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers extracted from lib/spec.cpp for unit testing.

#pragma once

#include <map>
#include <string>
#include <utility>

namespace SpecPure {

typedef std::pair<unsigned, unsigned> PortRange;

PortRange parsePortRange(const std::string &str);

// Replace ${KEY} tokens in `input` with values from `vars`.
// No-op if vars is empty. Substitution is multi-pass per key.
std::string substituteVars(const std::string &input,
                           const std::map<std::string, std::string> &vars);

}
