// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "locs.h"
#include "jail_query.h"
#include "runtime_paths_pure.h"
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
// Uses libjail API via JailQuery (replaces jls parsing).
static bool resolveContainer(const std::string &target, int &outJid, std::string &outPath) {

  // Try direct lookup by name first
  auto jail = JailQuery::getJailByName(target);
  if (!jail) {
    try {
      int jid = std::stoi(target);
      jail = JailQuery::getJailByJid(jid);
    } catch (...) {}
  }

  if (jail && RuntimePathsPure::isCrateJailPath(jail->path)) {
    outJid = jail->jid;
    outPath = jail->path;
    return true;
  }

  // Fall back to scanning all crate jails for partial match
  auto jails = JailQuery::getAllJails(true);
  for (auto &j : jails) {
    auto name = RuntimePathsPure::crateJailDirName(j.path);   // "jail-<name>-<hex>"
    bool match = false;
    try { match = (std::stoi(target) == j.jid); } catch (...) {}
    if (!match) match = (name == target);
    if (!match) match = (name.find("jail-" + target) == 0);
    if (!match) match = (j.hostname == target);
    if (match) {
      outJid = j.jid;
      outPath = j.path;
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

  // 1.1.39: jexec(8) execvp()s argv[0] literally — there is no shell
  // between us and it — so "login -f <user>" as ONE argv element meant
  // "run a program called `login -f root`" and every interactive
  // `crate console` failed with "No such file or directory". Each word
  // is its own argv element now, and the extra `-- args` are appended
  // verbatim (no shell quoting, since nothing unquotes them).
  std::vector<std::string> innerArgv;
  if (args.consoleCmd.empty()) {
    innerArgv.push_back("/usr/bin/login");
    innerArgv.push_back("-f");
    innerArgv.push_back(consoleUser);
  } else {
    innerArgv.push_back(args.consoleCmd);
  }
  for (int i = 0; i < argc; i++)
    innerArgv.push_back(argv[i]);

  // 1.1.40: unprivileged operator — the exec goes through crated's
  // exec_in_jail verb (our terminal travels as descriptors; the jid
  // must be registered to us). Root keeps the direct jexec -l path,
  // which also gives login(1) the clean environment it expects.
  if (::geteuid() != 0) {
    int status = JailExec::execInJail(jid, innerArgv, consoleUser, "console into jail");
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
  }

  std::vector<std::string> execArgv;
  execArgv.push_back(CRATE_PATH_JEXEC);
  execArgv.push_back("-l");
  execArgv.push_back("-U");
  execArgv.push_back(consoleUser);
  execArgv.push_back(jidStr);
  for (const auto &a : innerArgv)
    execArgv.push_back(a);

  // Execute — this replaces the process for interactive use via fork+exec
  int status = Util::execCommandGetStatus(execArgv, "console into jail");
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
