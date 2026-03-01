// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "locs.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <pwd.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define ERR(msg...) \
  ERR2("console", msg)

// Resolve a container target (name or JID) to its JID and path.
// Same logic as info.cpp — searches jls output for crate jails.
static bool resolveContainer(const std::string &target, int &outJid, std::string &outPath) {
  std::string output;
  try {
    output = Util::execCommandGetOutput({CRATE_PATH_JLS, "-N"}, "list jails");
  } catch (...) {
    return false;
  }

  auto cratePrefix = std::string(Locations::jailDirectoryPath) + "/jail-";
  std::istringstream is(output);
  std::string line;
  bool header = true;
  while (std::getline(is, line)) {
    if (header) { header = false; continue; }
    if (line.empty()) continue;
    std::istringstream ls(line);
    int jid;
    std::string ip, hostname, path;
    ls >> jid >> ip >> hostname >> path;
    if (path.find(cratePrefix) != 0)
      continue;
    auto name = path.substr(std::string(Locations::jailDirectoryPath).size() + 1);
    bool match = false;
    try { match = (std::stoi(target) == jid); } catch (...) {}
    if (!match) match = (name == target);
    if (!match) match = (name.find("jail-" + target) == 0);
    if (!match) match = (hostname == target);
    if (match) {
      outJid = jid;
      outPath = path;
      return true;
    }
  }
  return false;
}

bool consoleCrate(const Args &args, int argc, char** argv) {
  int jid;
  std::string path;

  if (!resolveContainer(args.consoleTarget, jid, path))
    ERR("container '" << args.consoleTarget << "' not found (not running or not a crate jail)")

  auto jidStr = std::to_string(jid);

  // Determine user: use the invoking user's name (same as run.cpp pattern)
  struct passwd *pw = ::getpwuid(::getuid());
  std::string consoleUser = args.consoleUser;
  if (consoleUser.empty()) {
    if (pw && pw->pw_name)
      consoleUser = pw->pw_name;
    else
      consoleUser = "root";
  }

  // Build the command to execute inside the jail
  std::vector<std::string> execArgv;
  execArgv.push_back(CRATE_PATH_JEXEC);
  execArgv.push_back("-l");
  execArgv.push_back("-U");
  execArgv.push_back(consoleUser);
  execArgv.push_back(jidStr);

  if (args.consoleCmd.empty()) {
    // Interactive login shell
    execArgv.push_back(STR("login -f " << consoleUser));
  } else {
    // Specific command
    execArgv.push_back(args.consoleCmd);
  }

  // Append any extra arguments passed after --
  for (int i = 0; i < argc; i++)
    execArgv.back() += STR(" " << Util::shellQuote(argv[i]));

  // Execute — this replaces the process for interactive use via fork+exec
  int status = Util::execCommandGetStatus(execArgv, "console into jail");
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
