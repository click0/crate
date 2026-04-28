// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "scripts.h"
#include "scripts_pure.h"
#include "util.h"

#include <rang.hpp>

#include <string>
#include <map>
#include <iostream>
#include <ostream>

namespace Scripts {

// escape moved to lib/scripts_pure.cpp (ScriptsPure::escape).
using ScriptsPure::escape;

//
// interface
//

void section(const char *sec, const std::map<std::string, std::map<std::string, std::string>> &scripts, FnRunner fnRunner) {
  auto it = scripts.find(sec);
  if (it != scripts.end())
    for (auto &script : it->second)
      fnRunner(STR("/bin/sh -c '" << escape(Util::pathSubstituteVarsInString(script.second)) << "'"));
}

}
