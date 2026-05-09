// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "audit_per_user.h"

#include "../lib/runtime_paths_pure.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

namespace Crated {

namespace {

// Best-effort mkdir of one directory. Idempotent (EEXIST is success).
// Mode 0700: only the operator's uid (and root) can read their audit.
bool mkdirIfNeeded(const std::string &dir, mode_t mode) {
  if (::mkdir(dir.c_str(), mode) == 0) return true;
  if (errno == EEXIST) return true;
  return false;
}

} // anon

bool appendPerUserAuditLine(uint32_t uid, const std::string &jsonLine) {
  // Skip the no-uid case silently — caller's choice not to wire
  // uid context yet (e.g. main bearer-token API in 0.9.13).
  if (uid == 0) return false;

  std::string dir = RuntimePathsPure::perUserRoot(uid);
  std::string path = RuntimePathsPure::perUserAuditLog(uid);

  if (!mkdirIfNeeded(dir, 0700)) {
    std::fprintf(stderr,
        "audit_per_user: mkdir(%s) failed: %s\n",
        dir.c_str(), std::strerror(errno));
    return false;
  }

  int fd = ::open(path.c_str(),
                  O_WRONLY | O_APPEND | O_CREAT,
                  0600);
  if (fd < 0) {
    std::fprintf(stderr,
        "audit_per_user: open(%s) failed: %s\n",
        path.c_str(), std::strerror(errno));
    return false;
  }

  // One line + '\n'. POSIX guarantees append-mode writes <= PIPE_BUF
  // are atomic; one privops audit line is under 200 bytes so we're
  // well under the kernel limit.
  std::string buf = jsonLine + "\n";
  ssize_t total = 0;
  while (total < (ssize_t)buf.size()) {
    ssize_t n = ::write(fd, buf.data() + total, buf.size() - total);
    if (n < 0) {
      if (errno == EINTR) continue;
      std::fprintf(stderr,
          "audit_per_user: write(%s) failed: %s\n",
          path.c_str(), std::strerror(errno));
      ::close(fd);
      return false;
    }
    total += n;
  }
  ::close(fd);
  return true;
}

} // namespace Crated
