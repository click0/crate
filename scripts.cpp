// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "scripts.h"
#include "util.h"

#include <rang.hpp>

#include <string>
#include <map>
#include <iostream>
#include <ostream>

namespace Scripts {

//
// helpers
//

static std::string escape(const std::string &script) {
  // Escape for embedding inside single quotes passed to /bin/sh -c '...'
  // Inside single quotes, only the single quote itself needs escaping.
  // We end the current single-quoted string, add an escaped literal quote,
  // and reopen the single-quoted string: ' → '\''
  std::ostringstream ss;
  for (auto chr : script)
    if (chr == '\'')
      ss << "'\\''";
    else
      ss << chr;
  return ss.str();
}

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
