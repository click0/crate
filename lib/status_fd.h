// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.65 (TODO §17.8): the I/O side of the `--status-fd` lifecycle
// stream whose format is lib/status_pure.h.
//
//   Writer      — `crate run` writes events to the operator's descriptor
//   spawnCrateRun / waitForJail
//               — a parent (`crate stack up`, crated) starts a detached
//                 `crate run --status-fd 3 ...` over a pipe and reads the
//                 stream until the jail exists, instead of polling
//                 jls(8) for a "<name>_pid<pid>" jail to show up.

#pragma once

#include "status_pure.h"

#include <mutex>
#include <string>
#include <vector>

#include <sys/types.h>

namespace StatusFd {

// The `crate run` side. Disabled (every emit() a no-op) for fd < 0.
class Writer {
public:
  explicit Writer(int fd = -1) : fd_(fd) {}
  bool enabled() const { return fd_ >= 0; }

  // Check the descriptor is open and mark it close-on-exec, so no
  // process started inside the jail inherits the operator's status
  // pipe. Returns "" or the reason the fd cannot be used.
  std::string open();

  // Write one line. A consumer that went away (EPIPE) silently
  // disables the writer; SIGPIPE is blocked around the write so a
  // closed pipe never kills the jail's supervisor. Thread-safe.
  void emit(const std::string &event, const std::vector<StatusPure::Field> &fields = {});

private:
  int fd_;
  std::mutex mu_;
};

// A detached `crate run` child with the read end of its status pipe.
// pid < 0 when the fork (or the pipe) failed; statusFd is then -1.
struct Spawned {
  pid_t pid = -1;
  int statusFd = -1;
};

// fork + setsid + stdio to /dev/null + execv(CRATE_PATH_CRATE, "crate",
// "run", <runArgs...>, "--status-fd", "3"), with the pipe's write end as
// fd 3 in the child. The parent gets the read end (close-on-exec).
// `runArgs` is everything after `run` (e.g. {"-f", file}); the caller
// closes statusFd (waitForJail does).
Spawned spawnCrateRun(const std::vector<std::string> &runArgs);

enum class Wait {
  JailCreated,   // `out` is the jail_created event (jid, name, path)
  Exited,        // the run ended before a jail existed (`out` = exited)
  Failed,        // the run threw (`out` = failed, "error" field)
  Eof,           // the stream closed without any of the above
  ChildGone,     // the child exited (reaped) before writing a terminal event
  Timeout        // nothing decisive within timeoutSec
};

// Read the stream on `fd` until one of the outcomes above. Always
// closes `fd` before returning; when the jail was created the child
// keeps running and its later writes get EPIPE, which the Writer
// treats as "nobody listening". `pid` (when > 0) is polled with
// waitpid(WNOHANG) so a supervisor that dies without a word is noticed
// at once, and reaped.
Wait waitForJail(int fd, pid_t pid, unsigned timeoutSec, StatusPure::Event &out);

// Human text for a Wait outcome, for the caller's error line.
std::string describe(Wait w, const StatusPure::Event &ev);

}
