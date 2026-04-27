// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "lifecycle_pure.h"

#include <iomanip>
#include <sstream>

namespace LifecyclePure {

#define LP_STR(x) static_cast<std::ostringstream&&>(std::ostringstream() << x).str()

std::string humanBytes(uint64_t bytes) {
  if (bytes >= (1ULL << 30))
    return LP_STR(std::fixed << std::setprecision(1)
                  << (double)bytes / (1ULL << 30) << "G");
  if (bytes >= (1ULL << 20))
    return LP_STR(std::fixed << std::setprecision(1)
                  << (double)bytes / (1ULL << 20) << "M");
  if (bytes >= (1ULL << 10))
    return LP_STR(std::fixed << std::setprecision(1)
                  << (double)bytes / (1ULL << 10) << "K");
  return LP_STR(bytes << "B");
}

}
