// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Jail query and exec using libjail C API (jailparam_*).
// Fallback to jls(8)/jexec(8) when API calls fail.

#include "jail_query.h"
#include "locs.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

// sys/jail.h isn't C++-safe: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=238928
#include <sys/param.h>
extern "C" {
#include <sys/jail.h>
}
#include <jail.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <string>

#define ERR(msg...) ERR2("jail query", msg)

// ---------------------------------------------------------------------------
// JailQuery: libjail-based jail enumeration (replaces jls)
// ---------------------------------------------------------------------------

namespace JailQuery {

// RAII wrapper for jailparam array.
struct JailParamSet {
  struct jailparam *params = nullptr;
  unsigned count = 0;

  JailParamSet() = default;
  ~JailParamSet() {
    if (params) {
      jailparam_free(params, count);
      ::free(params);
    }
  }
  JailParamSet(const JailParamSet&) = delete;
  JailParamSet& operator=(const JailParamSet&) = delete;

  bool init(const std::vector<std::string> &names) {
    count = static_cast<unsigned>(names.size());
    params = static_cast<struct jailparam*>(::calloc(count, sizeof(struct jailparam)));
    if (!params) return false;
    for (unsigned i = 0; i < count; i++) {
      if (jailparam_init(&params[i], names[i].c_str()) == -1) {
        // Partial init — free what we have and fail
        jailparam_free(params, i);
        ::free(params);
        params = nullptr;
        count = 0;
        return false;
      }
    }
    return true;
  }

  std::string getString(unsigned idx) const {
    if (!params || idx >= count) return "";
    char *val = jailparam_export(&params[idx]);
    if (!val) return "";
    std::string result(val);
    ::free(val);
    return result;
  }

  int getInt(unsigned idx) const {
    auto s = getString(idx);
    if (s.empty()) return 0;
    try { return std::stoi(s); } catch (...) { return 0; }
  }
};

// Query a single jail by providing filter params.
// Returns nullopt if jail not found.
static std::optional<JailInfo> queryOneJail(
    const std::string &filterName, const std::string &filterValue) {

  // Parameters we want to retrieve
  std::vector<std::string> names = {
    filterName, "jid", "name", "path", "host.hostname", "ip4.addr", "dying"
  };

  JailParamSet ps;
  if (!ps.init(names))
    return std::nullopt;

  // Set the filter value
  if (jailparam_import(&ps.params[0], filterValue.c_str()) == -1)
    return std::nullopt;

  int jid = jailparam_get(ps.params, ps.count, 0);
  if (jid == -1)
    return std::nullopt;

  JailInfo info;
  info.jid      = ps.getInt(1);
  info.name     = ps.getString(2);
  info.path     = ps.getString(3);
  info.hostname = ps.getString(4);
  info.ip4      = ps.getString(5);
  info.dying    = (ps.getString(6) == "true" || ps.getString(6) == "1");
  return info;
}

// Fallback: parse jls -N output.
static std::vector<JailInfo> fallbackGetAllJails() {
  std::vector<JailInfo> result;
  std::string output;
  try {
    output = Util::execCommandGetOutput(
      {CRATE_PATH_JLS, "-N"}, "list jails (fallback)");
  } catch (...) {
    return result;
  }

  std::istringstream is(output);
  std::string line;
  bool header = true;
  while (std::getline(is, line)) {
    if (header) { header = false; continue; }
    if (line.empty()) continue;
    std::istringstream ls(line);
    JailInfo info;
    std::string ipStr;
    ls >> info.jid >> ipStr >> info.hostname >> info.path;
    info.ip4 = (ipStr == "-") ? "" : ipStr;
    // Derive name from path (last component)
    auto pos = info.path.rfind('/');
    if (pos != std::string::npos)
      info.name = info.path.substr(pos + 1);
    result.push_back(info);
  }
  return result;
}

std::vector<JailInfo> getAllJails(bool crateOnly) {
  std::vector<JailInfo> result;
  auto cratePrefix = std::string(Locations::jailDirectoryPath) + "/jail-";

  // Try native jailparam iteration: walk lastjid
  std::vector<std::string> names = {"lastjid", "jid", "name", "path",
                                     "host.hostname", "ip4.addr", "dying"};
  JailParamSet ps;
  if (!ps.init(names)) {
    // Fallback to jls
    auto fallback = fallbackGetAllJails();
    if (crateOnly) {
      for (auto &j : fallback)
        if (j.path.find(cratePrefix) == 0)
          result.push_back(j);
      return result;
    }
    return fallback;
  }

  // Import lastjid=0 to start iteration
  if (jailparam_import(&ps.params[0], "0") == -1) {
    auto fallback = fallbackGetAllJails();
    if (crateOnly) {
      for (auto &j : fallback)
        if (j.path.find(cratePrefix) == 0)
          result.push_back(j);
      return result;
    }
    return fallback;
  }

  // Iterate: jailparam_get with JAIL_DYING flag to see all jails
  while (true) {
    int jid = jailparam_get(ps.params, ps.count, JAIL_DYING);
    if (jid == -1)
      break;

    JailInfo info;
    info.jid      = ps.getInt(1);
    info.name     = ps.getString(2);
    info.path     = ps.getString(3);
    info.hostname = ps.getString(4);
    info.ip4      = ps.getString(5);
    info.dying    = (ps.getString(6) == "true" || ps.getString(6) == "1");

    if (crateOnly && info.path.find(cratePrefix) != 0)
      continue;

    result.push_back(info);

    // Advance lastjid for next iteration
    auto nextJid = std::to_string(info.jid);
    jailparam_import(&ps.params[0], nextJid.c_str());
  }

  return result;
}

std::optional<JailInfo> getJailByName(const std::string &name) {
  auto result = queryOneJail("name", name);
  if (result) return result;

  // Fallback: try jls
  auto all = fallbackGetAllJails();
  for (auto &j : all)
    if (j.name == name)
      return j;
  return std::nullopt;
}

std::optional<JailInfo> getJailByJid(int jid) {
  auto result = queryOneJail("jid", std::to_string(jid));
  if (result) return result;

  // Fallback
  auto all = fallbackGetAllJails();
  for (auto &j : all)
    if (j.jid == jid)
      return j;
  return std::nullopt;
}

std::string getJailParam(int jid, const std::string &paramName) {
  std::vector<std::string> names = {"jid", paramName};
  JailParamSet ps;
  if (!ps.init(names))
    return "";
  if (jailparam_import(&ps.params[0], std::to_string(jid).c_str()) == -1)
    return "";
  if (jailparam_get(ps.params, ps.count, 0) == -1)
    return "";
  return ps.getString(1);
}

int getJidByName(const std::string &name) {
  int jid = ::jail_getid(name.c_str());
  if (jid >= 0) return jid;

  // Fallback
  auto info = getJailByName(name);
  return info ? info->jid : -1;
}

}

// ---------------------------------------------------------------------------
// JailExec: jail_attach()-based execution (replaces jexec)
// ---------------------------------------------------------------------------

namespace JailExec {

// Build C argv from vector.
static std::vector<char*> buildArgv(const std::vector<std::string> &args) {
  std::vector<char*> argv;
  for (auto &a : args)
    argv.push_back(const_cast<char*>(a.c_str()));
  argv.push_back(nullptr);
  return argv;
}

// Fallback: use jexec(8) via fork+exec.
static int fallbackJexec(int jid, const std::vector<std::string> &argv,
                         const std::string &user, const std::string &what,
                         std::string *captureOutput) {
  std::vector<std::string> jexecArgv = {CRATE_PATH_JEXEC, "-l"};
  if (!user.empty() && user != "root") {
    jexecArgv.push_back("-U");
    jexecArgv.push_back(user);
  }
  jexecArgv.push_back(std::to_string(jid));
  for (auto &a : argv)
    jexecArgv.push_back(a);

  if (captureOutput) {
    *captureOutput = Util::execCommandGetOutput(jexecArgv, what);
    return 0;
  }
  return Util::execCommandGetStatus(jexecArgv, what);
}

int execInJail(int jid, const std::vector<std::string> &argv,
               const std::string &user, const std::string &what) {
  // Try jail_attach() approach
  pid_t pid = ::fork();
  if (pid == -1)
    ERR("fork failed: " << strerror(errno))

  if (pid == 0) {
    // Child: attach to jail, then exec
    if (::jail_attach(jid) == -1)
      ::_exit(126); // signal fallback needed

    // Switch user if needed
    if (!user.empty() && user != "root") {
      struct passwd *pw = ::getpwnam(user.c_str());
      if (pw) {
        ::initgroups(user.c_str(), pw->pw_gid);
        ::setgid(pw->pw_gid);
        ::setuid(pw->pw_uid);
      }
    }

    auto cargv = buildArgv(argv);
    ::execv(argv[0].c_str(), cargv.data());
    ::_exit(127); // exec failed
  }

  // Parent: wait for child
  int status;
  ::waitpid(pid, &status, 0);

  // If child exited with 126, jail_attach failed — use jexec fallback
  if (WIFEXITED(status) && WEXITSTATUS(status) == 126)
    return fallbackJexec(jid, argv, user, what, nullptr);

  return status;
}

std::string execInJailGetOutput(int jid, const std::vector<std::string> &argv,
                                const std::string &user, const std::string &what) {
  // For output capture, use pipe
  int pipefd[2];
  if (::pipe(pipefd) == -1)
    ERR("pipe failed: " << strerror(errno))

  pid_t pid = ::fork();
  if (pid == -1) {
    ::close(pipefd[0]);
    ::close(pipefd[1]);
    ERR("fork failed: " << strerror(errno))
  }

  if (pid == 0) {
    // Child
    ::close(pipefd[0]);
    ::dup2(pipefd[1], STDOUT_FILENO);
    ::close(pipefd[1]);

    if (::jail_attach(jid) == -1)
      ::_exit(126);

    if (!user.empty() && user != "root") {
      struct passwd *pw = ::getpwnam(user.c_str());
      if (pw) {
        ::initgroups(user.c_str(), pw->pw_gid);
        ::setgid(pw->pw_gid);
        ::setuid(pw->pw_uid);
      }
    }

    auto cargv = buildArgv(argv);
    ::execv(argv[0].c_str(), cargv.data());
    ::_exit(127);
  }

  // Parent: read from pipe
  ::close(pipefd[1]);

  std::string output;
  char buf[4096];
  ssize_t n;
  while ((n = ::read(pipefd[0], buf, sizeof(buf))) > 0)
    output.append(buf, n);
  ::close(pipefd[0]);

  int status;
  ::waitpid(pid, &status, 0);

  // Fallback if jail_attach failed
  if (WIFEXITED(status) && WEXITSTATUS(status) == 126) {
    std::string fallbackOutput;
    fallbackJexec(jid, argv, user, what, &fallbackOutput);
    return fallbackOutput;
  }

  return output;
}

void execInJailChecked(int jid, const std::vector<std::string> &argv,
                       const std::string &user, const std::string &what) {
  int status = execInJail(jid, argv, user, what);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    ERR(what << ": command failed with status " << WEXITSTATUS(status))
}

}
