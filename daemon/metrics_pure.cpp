// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "metrics_pure.h"

#include <sstream>

namespace MetricsPure {

std::map<std::string, std::string> parseRctlUsage(const std::string &rctlOutput) {
  std::map<std::string, std::string> result;
  std::istringstream is(rctlOutput);
  std::string line;
  while (std::getline(is, line)) {
    auto eqPos = line.find('=');
    if (eqPos == std::string::npos) continue;
    result[line.substr(0, eqPos)] = line.substr(eqPos + 1);
  }
  return result;
}

}
