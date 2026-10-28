// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "dir_lock.h"
#include "err.h"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#define ERR(msg...) ERR2("dir-lock", msg)

namespace DirLock {

void Guard::acquire(const std::string &path) {
  release();
  int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0)
    ERR("cannot open " << path << ": " << std::strerror(errno))
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
    int e = errno;
    ::close(fd);
    if (e == EWOULDBLOCK)
      ERR(path << " is in use by another crate process")
    ERR("flock " << path << ": " << std::strerror(e))
  }
  fd_ = fd;
}

void Guard::release() {
  if (fd_ >= 0) { ::close(fd_); fd_ = -1; }   // close drops the flock
}

bool isLocked(const std::string &path) {
  int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return false;
  bool locked = false;
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0)
    locked = (errno == EWOULDBLOCK);
  ::close(fd);   // releases our probe lock when we got it
  return locked;
}

} // namespace DirLock
