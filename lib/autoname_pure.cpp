// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "autoname_pure.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace AutoNamePure {

std::string snapshotName() {
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  std::ostringstream ss;
  ss << std::put_time(std::gmtime(&time), "%Y%m%dT%H%M%S");
  return ss.str();
}

std::string exportName(const std::string &baseName) {
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  std::ostringstream ss;
  ss << baseName << "-" << std::put_time(std::gmtime(&time), "%Y%m%d-%H%M%S") << ".crate";
  return ss.str();
}

}
