// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "scripts_pure.h"
#include "pathnames.h"

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

HookPlace hookPlace(const std::string &section) {
  if (section == "run:begin" || section == "run:before-create-jail" ||
      section == "run:after-remove-jail")
    return HookPlace::ThrowAway;
  return HookPlace::InJail;
}

std::string firstThrowAwaySection(const std::vector<std::string> &sections) {
  for (const char *s : {"run:begin", "run:before-create-jail", "run:after-remove-jail"})
    for (const auto &have : sections)
      if (have == s) return s;
  return "";
}

std::vector<std::string> throwAwayJailArgv(const std::string &jailPath,
                                           const std::string &commandLine,
                                           bool inet6) {
  std::vector<std::string> argv = {CRATE_PATH_JAIL, "-c", "path=" + jailPath, "ip4=inherit"};
  if (inet6) argv.push_back("ip6=inherit");
  argv.push_back(std::string("command=") + CRATE_PATH_SH);
  argv.push_back("-c");
  argv.push_back(commandLine);
  return argv;
}

}
