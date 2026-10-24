// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Runtime for `crate profile-from-trace` (1.1.60, TODO §17.3). Runs the
// command once under truss(1) on the HOST — unsandboxed, with crate's
// sanitised environment — or reads a saved truss output, asks `pkg which`
// who owns the /usr/local files it touched, and prints the spec draft
// TracePure::generate derives from it. Nothing here is privileged.
//

#include "args.h"
#include "trace_pure.h"
#include "pathnames.h"
#include "version.h"
#include "util.h"
#include "err.h"
#include "commands.h"

#include <rang.hpp>

#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#define ERR(msg...) ERR2("profile-from-trace", msg)

namespace {

// `pkg which` exits non-zero when any path is not owned, and
// Util::execCommandGetOutput discards the output on a non-zero exit —
// here the "not found" lines are part of the answer, so capture
// stdout+stderr regardless of the status.
std::string captureOutput(const std::vector<std::string> &argv) {
  int fds[2];
  if (::pipe2(fds, O_CLOEXEC) == -1)
    ERR("pipe: " << strerror(errno))
  pid_t pid = ::fork();
  if (pid == -1) {
    int e = errno;
    ::close(fds[0]); ::close(fds[1]);
    ERR("fork: " << strerror(e))
  }
  if (pid == 0) {
    ::dup2(fds[1], STDOUT_FILENO);
    ::dup2(fds[1], STDERR_FILENO);
    std::vector<char *> cargv;
    for (auto &a : argv) cargv.push_back(const_cast<char *>(a.c_str()));
    cargv.push_back(nullptr);
    ::execv(cargv[0], cargv.data());
    ::_exit(127);
  }
  ::close(fds[1]);
  std::ostringstream out;
  char buf[4096];
  ssize_t n;
  while ((n = ::read(fds[0], buf, sizeof buf)) > 0) out.write(buf, n);
  ::close(fds[0]);
  int st;
  while (::waitpid(pid, &st, 0) == -1 && errno == EINTR) {}
  return out.str();
}

std::vector<std::string> readLines(const std::string &path) {
  std::ifstream f(path);
  if (!f) ERR("cannot read " << path << ": " << strerror(errno))
  std::vector<std::string> lines;
  std::string l;
  while (std::getline(f, l)) lines.push_back(l);
  return lines;
}

} // namespace

bool profileFromTraceCommand(const Args &args, int argc, char **argv) {
  std::vector<std::string> cmd;
  for (int i = 0; i < argc; i++) cmd.push_back(argv[i]);

  std::vector<std::string> lines;
  if (!args.traceFile.empty()) {
    if (!cmd.empty())
      ERR("--trace-file and a command to trace are mutually exclusive")
    lines = readLines(args.traceFile);
  } else {
    if (cmd.empty())
      ERR("give the command to trace after '--', or --trace-file <truss output>")
    if (!Util::Fs::fileExists(CRATE_PATH_TRUSS))
      ERR(CRATE_PATH_TRUSS << " is missing (truss(1) is part of the base system)")

    std::string traceOut = args.traceKeep;
    bool temporary = traceOut.empty();
    if (temporary) {
      char tmpl[] = "/tmp/crate-trace-XXXXXX";
      int fd = ::mkstemp(tmpl);
      if (fd == -1) ERR("mkstemp: " << strerror(errno))
      ::close(fd);
      traceOut = tmpl;
    }

    std::vector<std::string> truss = {CRATE_PATH_TRUSS, "-f", "-s", "1024", "-o", traceOut, "--"};
    truss.insert(truss.end(), cmd.begin(), cmd.end());
    std::cerr << rang::fg::blue << "profile-from-trace: running on the host (not sandboxed) under truss:";
    for (auto &w : cmd) std::cerr << " " << w;
    std::cerr << rang::style::reset << std::endl;
    int st = Util::execCommandGetStatus(truss, "truss");
    if (WIFEXITED(st) && WEXITSTATUS(st) == 127)
      ERR("could not start truss")
    std::cerr << rang::fg::blue << "profile-from-trace: the program "
              << (WIFEXITED(st) ? "exited with status " + std::to_string(WEXITSTATUS(st))
                                : "was terminated by a signal")
              << rang::style::reset << std::endl;
    lines = readLines(traceOut);
    if (temporary) ::unlink(traceOut.c_str());
    else std::cerr << rang::fg::blue << "profile-from-trace: raw trace kept at " << traceOut
                   << rang::style::reset << std::endl;
  }

  auto summary = TracePure::summarize(lines);
  if (summary.parsed == 0)
    ERR("no syscalls recognised in " << summary.lines << " lines — is this truss(1) output?")

  TracePure::Input in;
  in.home = Util::Fs::getUserHomeDir();
  in.command = cmd;

  // who owns the /usr/local files: one `pkg which` per 200 paths
  std::set<std::string> local;
  for (auto &p : summary.execs) if (p.compare(0, 11, "/usr/local/") == 0) local.insert(p);
  for (auto *paths : {&summary.readPaths, &summary.writePaths})
    for (auto &p : *paths) if (p.compare(0, 11, "/usr/local/") == 0) local.insert(p);
  if (!local.empty()) {
    if (!Util::Fs::fileExists(CRATE_PATH_PKG)) {
      std::cerr << rang::fg::yellow << "profile-from-trace: " << CRATE_PATH_PKG
                << " not found; pkg/install cannot be derived" << rang::style::reset << std::endl;
    } else {
      std::vector<std::string> batch = {CRATE_PATH_PKG, "which"};
      auto flush = [&]() {
        if (batch.size() <= 2) return;
        auto owners = TracePure::parsePkgWhichOutput(captureOutput(batch));
        in.pkgOwner.insert(owners.begin(), owners.end());
        batch.resize(2);
      };
      for (auto &p : local) {
        batch.push_back(p);
        if (batch.size() >= 202) flush();
      }
      flush();
    }
  }

  auto gen = TracePure::generate(summary, in);
  auto text = TracePure::renderSpec(gen, CRATE_VERSION);

  if (args.traceOutput.empty()) {
    std::cout << text;
  } else {
    Util::Fs::writeFile(text, args.traceOutput);
    std::cerr << rang::fg::blue << "profile-from-trace: spec draft written to " << args.traceOutput
              << " (" << summary.parsed << " syscalls, " << summary.execs.size() << " programs, "
              << summary.outbound.size() << " destinations)" << rang::style::reset << std::endl;
  }
  return true;
}
