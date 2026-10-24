// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "status_fd.h"
#include "pathnames.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

namespace StatusFd {

std::string Writer::open() {
  if (fd_ < 0) return "";
  int flags = ::fcntl(fd_, F_GETFD);
  if (flags < 0) {
    std::string e = "--status-fd " + std::to_string(fd_) + ": not an open descriptor (" + std::strerror(errno)
                    + "); the caller has to open it, e.g. `3>status.jsonl`";
    fd_ = -1;
    return e;
  }
  (void)::fcntl(fd_, F_SETFD, flags | FD_CLOEXEC);
  return "";
}

void Writer::emit(const std::string &event, const std::vector<StatusPure::Field> &fields) {
  std::lock_guard<std::mutex> lk(mu_);
  if (fd_ < 0) return;
  const std::string line = StatusPure::renderLine(event, (long long)::time(nullptr), fields);

  // Block SIGPIPE for this thread around the write (same pattern as
  // Util::execCommandWithInput): a reader that closed its end must not
  // kill the jail's supervisor; the write fails with EPIPE instead and
  // the stream is simply switched off.
  sigset_t block, old;
  sigemptyset(&block);
  sigaddset(&block, SIGPIPE);
  pthread_sigmask(SIG_BLOCK, &block, &old);
  size_t off = 0;
  bool failed = false;
  while (off < line.size()) {
    ssize_t n = ::write(fd_, line.data() + off, line.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      failed = true;
      break;
    }
    off += (size_t)n;
  }
  sigset_t pending;
  sigpending(&pending);
  if (sigismember(&pending, SIGPIPE)) {
    struct timespec zero{0, 0};
    (void)::sigtimedwait(&block, nullptr, &zero);
  }
  pthread_sigmask(SIG_SETMASK, &old, nullptr);
  if (failed) fd_ = -1;   // EPIPE, EBADF, ...: nobody is listening any more
}

Spawned spawnCrateRun(const std::vector<std::string> &runArgs) {
  Spawned s;
  int pfd[2];
  if (::pipe2(pfd, O_CLOEXEC) == -1) return s;
  std::vector<std::string> argv = {"crate", "run"};
  argv.insert(argv.end(), runArgs.begin(), runArgs.end());
  argv.push_back("--status-fd");
  argv.push_back("3");
  pid_t pid = ::fork();
  if (pid < 0) {
    ::close(pfd[0]);
    ::close(pfd[1]);
    return s;
  }
  if (pid == 0) {
    ::setsid();
    ::close(0); ::close(1); ::close(2);
    ::open("/dev/null", O_RDONLY);
    ::open("/dev/null", O_WRONLY);
    ::open("/dev/null", O_WRONLY);
    // the write end becomes fd 3 (dup2 clears close-on-exec on the copy)
    if (pfd[1] != 3) {
      if (::dup2(pfd[1], 3) < 0) ::_exit(126);
    } else {
      int fl = ::fcntl(3, F_GETFD);
      if (fl >= 0) ::fcntl(3, F_SETFD, fl & ~FD_CLOEXEC);
    }
    std::vector<char*> cargv;
    for (auto &a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);
    ::execv(CRATE_PATH_CRATE, cargv.data());
    ::_exit(127);
  }
  ::close(pfd[1]);
  s.pid = pid;
  s.statusFd = pfd[0];
  return s;
}

Wait waitForJail(int fd, pid_t pid, unsigned timeoutSec, StatusPure::Event &out) {
  struct Closer { int fd; ~Closer() { if (fd >= 0) ::close(fd); } } closer{fd};
  if (fd < 0) return Wait::Eof;
  StatusPure::LineBuffer lines;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSec);
  char buf[4096];
  for (;;) {
    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return Wait::Timeout;
    auto leftMs = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    struct pollfd p{fd, POLLIN, 0};
    int r = ::poll(&p, 1, (int)(leftMs < 500 ? leftMs : 500));
    if (r < 0) {
      if (errno == EINTR) continue;
      return Wait::Eof;
    }
    if (r > 0) {
      ssize_t n = ::read(fd, buf, sizeof buf);
      if (n < 0) {
        if (errno == EINTR) continue;
        return Wait::Eof;
      }
      bool eof = n == 0;
      if (eof) {
        std::string tail;
        if (lines.flush(tail)) lines.feed((tail + "\n").c_str(), tail.size() + 1);
      } else {
        lines.feed(buf, (size_t)n);
      }
      std::string line;
      while (lines.next(line)) {
        StatusPure::Event ev;
        if (!StatusPure::parseLine(line, ev)) continue;   // not ours: ignore
        if (ev.event == StatusPure::kJailCreated) { out = ev; return Wait::JailCreated; }
        if (ev.event == StatusPure::kExited)      { out = ev; return Wait::Exited; }
        if (ev.event == StatusPure::kFailed)      { out = ev; return Wait::Failed; }
      }
      if (eof) {
        if (pid > 0) {
          int st = 0;
          if (::waitpid(pid, &st, WNOHANG) == pid) return Wait::ChildGone;
        }
        return Wait::Eof;
      }
      continue;
    }
    // idle tick: a supervisor that died without writing anything
    if (pid > 0) {
      int st = 0;
      if (::waitpid(pid, &st, WNOHANG) == pid) return Wait::ChildGone;
    }
  }
}

std::string describe(Wait w, const StatusPure::Event &ev) {
  switch (w) {
    case Wait::JailCreated: return "jail " + ev.get("name") + " created (jid " + ev.get("jid") + ")";
    case Wait::Exited:      return "the run ended before its jail was up (exit code " + ev.get("code") + ", " + ev.get("reason") + ")";
    case Wait::Failed:      return "crate run failed: " + ev.get("error");
    case Wait::Eof:         return "the status stream closed before the jail was created";
    case Wait::ChildGone:   return "crate run exited before its jail was created";
    case Wait::Timeout:     return "no jail within the time limit";
  }
  return "";
}

}
