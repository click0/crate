// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers extracted from daemon/metrics.cpp for unit testing.

#pragma once

#include <map>
#include <string>

namespace MetricsPure {

// Parse rctl -u output ("resource=value\n" lines) into a key→value map.
std::map<std::string, std::string> parseRctlUsage(const std::string &rctlOutput);

}
