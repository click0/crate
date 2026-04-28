// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "scripts_pure.h"

#include <sstream>

namespace ScriptsPure {

std::string escape(const std::string &script) {
  std::ostringstream ss;
  for (auto chr : script)
    if (chr == '\'')
      ss << "'\\''";
    else
      ss << chr;
  return ss.str();
}

}
