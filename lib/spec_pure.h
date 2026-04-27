// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers extracted from lib/spec.cpp for unit testing.

#pragma once

#include <string>
#include <utility>

namespace SpecPure {

typedef std::pair<unsigned, unsigned> PortRange;

PortRange parsePortRange(const std::string &str);

}
