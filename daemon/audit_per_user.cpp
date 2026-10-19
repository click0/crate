// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "audit_per_user.h"

#include "../lib/runtime_paths_pure.h"

#include <fcntl.h>
#include <pwd.h>
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

std::string ensurePerUserRoot(uint32_t uid) {
  if (uid == 0) return "";   // root uses the legacy tree
  std::string dir = RuntimePathsPure::perUserRoot(uid);
  if (!mkdirIfNeeded(dir, 0700))
    return "mkdir(" + dir + "): " + std::strerror(errno);
  struct stat st{};
  if (::lstat(dir.c_str(), &st) != 0)
    return "lstat(" + dir + "): " + std::strerror(errno);
  if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode))
    return dir + " is not a directory";
  gid_t gid = (gid_t)-1;
  if (struct passwd *pw = ::getpwuid((uid_t)uid))
    gid = pw->pw_gid;
  if (st.st_uid != (uid_t)uid || (gid != (gid_t)-1 && st.st_gid != gid)) {
    if (::chown(dir.c_str(), (uid_t)uid, gid) != 0)
      return "chown(" + dir + "): " + std::strerror(errno);
  }
  if ((st.st_mode & 07777) != 0700 && ::chmod(dir.c_str(), 0700) != 0)
    return "chmod(" + dir + "): " + std::strerror(errno);
  return "";
}

bool appendPerUserAuditLine(uint32_t uid, const std::string &jsonLine) {
  // Skip the no-uid case silently — caller's choice not to wire
  // uid context yet (e.g. main bearer-token API in 0.9.13).
  if (uid == 0) return false;

  std::string dir = RuntimePathsPure::perUserRoot(uid);
  std::string path = RuntimePathsPure::perUserAuditLog(uid);

  if (auto e = ensurePerUserRoot(uid); !e.empty()) {
    std::fprintf(stderr, "audit_per_user: %s\n", e.c_str());
    return false;
  }

  // 1.1.41: the directory is OWNED BY THE OPERATOR since 1.1.39, so a
  // root open() by path in it must not follow anything the operator
  // planted: O_NOFOLLOW, then fstat — a plain file with one link,
  // owned by root (pre-1.1.41 file) or by the operator. Anything else
  // (symlink, hard link to some other file, fifo, directory) is
  // refused. A file we accept is handed to the operator (fchown) so
  // the "operator-readable copy" is actually readable, and crate(1)'s
  // own fallback (crate-audit.log, lib/audit.cpp) sits next to it.
  int fd = ::open(path.c_str(),
                  O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                  0600);
  if (fd < 0) {
    std::fprintf(stderr,
        "audit_per_user: open(%s) failed: %s\n",
        path.c_str(), std::strerror(errno));
    return false;
  }
  struct stat fst{};
  if (::fstat(fd, &fst) != 0 || !S_ISREG(fst.st_mode) || fst.st_nlink != 1 ||
      (fst.st_uid != 0 && fst.st_uid != (uid_t)uid)) {
    std::fprintf(stderr,
        "audit_per_user: %s is not a plain single-link file owned by root or uid %u"
        " — refusing to append\n", path.c_str(), (unsigned)uid);
    ::close(fd);
    return false;
  }
  if (fst.st_uid != (uid_t)uid)
    (void)::fchown(fd, (uid_t)uid, (gid_t)-1);

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
