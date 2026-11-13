// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "fs_beneath.h"
#include "err.h"

#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define ERR(msg...) ERR2("jail tree", msg)

namespace FsBeneath {

namespace {

// Closes on scope exit unless released.
struct Fd {
  int fd = -1;
  explicit Fd(int f = -1) : fd(f) {}
  ~Fd() { if (fd >= 0) ::close(fd); }
  Fd(const Fd&) = delete;
  Fd &operator=(const Fd&) = delete;
  int release() { int f = fd; fd = -1; return f; }
};

const int kDirFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;

std::string where(const std::string &root, const std::string &rel) {
  if (!rel.empty() && rel[0] == '/') return root + rel;
  return root + "/" + rel;
}

// Why `name` in `dfd` could not be opened: a symlink is named as such
// (O_NOFOLLOW reports ELOOP on Linux, EMLINK on FreeBSD).
std::string reason(int dfd, const std::string &name, int err) {
  struct stat st;
  if (dfd >= 0 && ::fstatat(dfd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode))
    return "'" + name + "' is a symbolic link, which is not followed from the host";
  return "'" + name + "': " + ::strerror(err);
}

struct Walk {
  std::vector<std::string> parts;
  int dfd = -1;          // the directory that holds parts.back(); -1 on failure
  int err = 0;           // errno of the failure
  std::string why;       // the failure, for a message
};

// Walk to the directory holding the last component of rel. With
// createMode != 0 missing directories are created (mkdirs).
Walk walkToParent(const std::string &root, const std::string &rel, mode_t createMode = 0) {
  Walk w;
  if (auto e = splitRelative(rel, w.parts); !e.empty()) {
    w.err = EINVAL;
    w.why = e;
    return w;
  }
  int dfd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd < 0) {
    w.err = errno;
    w.why = "'" + root + "': " + ::strerror(w.err);
    return w;
  }
  for (size_t i = 0; i + 1 < w.parts.size(); i++) {
    const std::string &name = w.parts[i];
    if (createMode != 0 && ::mkdirat(dfd, name.c_str(), createMode) != 0 && errno != EEXIST) {
      w.err = errno;
      w.why = "mkdir '" + name + "': " + ::strerror(w.err);
      ::close(dfd);
      return w;
    }
    int nfd = ::openat(dfd, name.c_str(), kDirFlags);
    if (nfd < 0) {
      w.err = errno;
      w.why = reason(dfd, name, w.err);
      ::close(dfd);
      return w;
    }
    ::close(dfd);
    dfd = nfd;
  }
  w.dfd = dfd;
  return w;
}

int openLeaf(const std::string &root, const std::string &rel, int flags, mode_t mode) {
  Walk w = walkToParent(root, rel);
  if (w.dfd < 0)
    ERR("'" << where(root, rel) << "': " << w.why)
  Fd dir(w.dfd);
  const std::string &leaf = w.parts.back();
  int fd = ::openat(dir.fd, leaf.c_str(), flags | O_NOFOLLOW | O_CLOEXEC, mode);
  if (fd < 0) {
    int err = errno;
    ERR("'" << where(root, rel) << "': " << reason(dir.fd, leaf, err))
  }
  return fd;
}

void requireRegular(int fd, const std::string &what) {
  struct stat st;
  if (::fstat(fd, &st) != 0)
    ERR("'" << what << "': fstat: " << ::strerror(errno))
  if (!S_ISREG(st.st_mode))
    ERR("'" << what << "' is not a regular file")
}

void writeAll(int fd, const char *data, size_t len, const std::string &what) {
  while (len > 0) {
    ssize_t n = ::write(fd, data, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      ERR("'" << what << "': write: " << ::strerror(errno))
    }
    data += n;
    len -= (size_t)n;
  }
}

void copyFd(int src, int dst, const std::string &what) {
  char buf[65536];
  for (;;) {
    ssize_t n = ::read(src, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) continue;
      ERR("'" << what << "': read: " << ::strerror(errno))
    }
    if (n == 0) break;
    writeAll(dst, buf, (size_t)n, what);
  }
}

void closeChecked(Fd &f, const std::string &what) {
  int fd = f.release();
  if (::close(fd) != 0)
    ERR("'" << what << "': close: " << ::strerror(errno))
}

// The copy at root + rel from the open regular file `src`.
void replaceWith(int src, const std::string &srcWhat, const std::string &root, const std::string &rel,
                 mode_t mode, uid_t uid, gid_t gid) {
  const std::string what = where(root, rel);
  Walk w = walkToParent(root, rel);
  if (w.dfd < 0)
    ERR("'" << what << "': " << w.why)
  Fd dir(w.dfd);
  const std::string &leaf = w.parts.back();
  struct stat st;
  if (::fstatat(dir.fd, leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
    if (S_ISDIR(st.st_mode))
      ERR("'" << what << "' is a directory")
    if (::unlinkat(dir.fd, leaf.c_str(), 0) != 0)
      ERR("'" << what << "': unlink: " << ::strerror(errno))
  }
  Fd dst(::openat(dir.fd, leaf.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (dst.fd < 0)
    ERR("'" << what << "': " << reason(dir.fd, leaf, errno))
  copyFd(src, dst.fd, srcWhat + " -> " + what);
  if (uid != (uid_t)-1 && ::fchown(dst.fd, uid, gid) != 0)
    ERR("'" << what << "': chown: " << ::strerror(errno))
  if (::fchmod(dst.fd, mode) != 0)
    ERR("'" << what << "': chmod: " << ::strerror(errno))
  closeChecked(dst, what);
}

} // anon

std::string splitRelative(const std::string &rel, std::vector<std::string> &parts) {
  parts.clear();
  if (rel.empty()) return "the path is empty";
  size_t i = 0;
  while (i < rel.size()) {
    while (i < rel.size() && rel[i] == '/') i++;
    if (i >= rel.size()) break;
    size_t j = rel.find('/', i);
    if (j == std::string::npos) j = rel.size();
    std::string name = rel.substr(i, j - i);
    if (name == "." || name == "..")
      return "'" + rel + "' has a '" + name + "' component";
    parts.push_back(std::move(name));
    i = j;
  }
  if (parts.empty()) return "'" + rel + "' names no file";
  return "";
}

int open(const std::string &root, const std::string &rel, int flags, mode_t mode) {
  return openLeaf(root, rel, flags, mode);
}

bool exists(const std::string &root, const std::string &rel) {
  Walk w = walkToParent(root, rel);
  if (w.dfd < 0) {
    if (w.err == ENOENT) return false;
    ERR("'" << where(root, rel) << "': " << w.why)
  }
  Fd dir(w.dfd);
  struct stat st;
  return ::fstatat(dir.fd, w.parts.back().c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0;
}

bool isDirectory(const std::string &root, const std::string &rel) {
  Walk w = walkToParent(root, rel);
  if (w.dfd < 0) {
    if (w.err == ENOENT) return false;
    ERR("'" << where(root, rel) << "': " << w.why)
  }
  Fd dir(w.dfd);
  struct stat st;
  return ::fstatat(dir.fd, w.parts.back().c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(st.st_mode);
}

void writeFile(const std::string &root, const std::string &rel, const std::string &data, mode_t mode) {
  const std::string what = where(root, rel);
  // O_NONBLOCK: a FIFO planted at rel fails here (ENXIO) or at the
  // regular-file check instead of blocking the open; no O_TRUNC before
  // that check.
  Fd f(openLeaf(root, rel, O_WRONLY | O_CREAT | O_NONBLOCK, mode));
  requireRegular(f.fd, what);
  if (::ftruncate(f.fd, 0) != 0)
    ERR("'" << what << "': truncate: " << ::strerror(errno))
  writeAll(f.fd, data.data(), data.size(), what);
  closeChecked(f, what);
}

void appendFile(const std::string &root, const std::string &rel, const std::string &data, mode_t mode) {
  const std::string what = where(root, rel);
  Fd f(openLeaf(root, rel, O_WRONLY | O_CREAT | O_APPEND | O_NONBLOCK, mode));
  requireRegular(f.fd, what);
  writeAll(f.fd, data.data(), data.size(), what);
  closeChecked(f, what);
}

void copyIn(const std::string &hostSrc, const std::string &root, const std::string &rel,
            mode_t mode, uid_t uid, gid_t gid) {
  Fd src(::open(hostSrc.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
  if (src.fd < 0)
    ERR("'" << hostSrc << "': " << ::strerror(errno))
  requireRegular(src.fd, hostSrc);
  replaceWith(src.fd, hostSrc, root, rel, mode, uid, gid);
}

void copyWithin(const std::string &root, const std::string &srcRel, const std::string &dstRel,
                mode_t mode, uid_t uid, gid_t gid) {
  const std::string srcWhat = where(root, srcRel);
  Fd src(openLeaf(root, srcRel, O_RDONLY | O_NONBLOCK, 0));
  requireRegular(src.fd, srcWhat);
  replaceWith(src.fd, srcWhat, root, dstRel, mode, uid, gid);
}

void copyOut(const std::string &root, const std::string &rel, const std::string &hostDst) {
  const std::string srcWhat = where(root, rel);
  Fd src(openLeaf(root, rel, O_RDONLY | O_NONBLOCK, 0));
  requireRegular(src.fd, srcWhat);
  Fd dst(::open(hostDst.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644));
  if (dst.fd < 0)
    ERR("'" << hostDst << "': " << ::strerror(errno))
  copyFd(src.fd, dst.fd, srcWhat + " -> " + hostDst);
  closeChecked(dst, hostDst);
}

void copyToNewFile(const std::string &hostSrc, const std::string &hostDst,
                   mode_t mode, uid_t uid, gid_t gid) {
  Fd src(::open(hostSrc.c_str(), O_RDONLY | O_CLOEXEC));
  if (src.fd < 0)
    ERR2("copy file", "cannot open '" << hostSrc << "': " << ::strerror(errno))
  Fd dst(::open(hostDst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode));
  if (dst.fd < 0)
    ERR2("copy file", "cannot create '" << hostDst << "': " << ::strerror(errno)
         << (errno == EEXIST ? " (a file or a symbolic link is already there)" : ""))
  try {
    copyFd(src.fd, dst.fd, hostDst);
    if (uid != (uid_t)-1 && ::fchown(dst.fd, uid, gid) != 0)
      ERR2("copy file", "'" << hostDst << "': fchown: " << ::strerror(errno))
    closeChecked(dst, hostDst);
  } catch (...) {
    (void)::unlink(hostDst.c_str());
    throw;
  }
}

void chown(const std::string &root, const std::string &rel, uid_t uid, gid_t gid) {
  const std::string what = where(root, rel);
  Fd f(openLeaf(root, rel, O_RDONLY | O_NONBLOCK, 0));
  if (::fchown(f.fd, uid, gid) != 0)
    ERR("'" << what << "': chown: " << ::strerror(errno))
}

void chmod(const std::string &root, const std::string &rel, mode_t mode) {
  const std::string what = where(root, rel);
  Fd f(openLeaf(root, rel, O_RDONLY | O_NONBLOCK, 0));
  if (::fchmod(f.fd, mode) != 0)
    ERR("'" << what << "': chmod: " << ::strerror(errno))
}

void unlink(const std::string &root, const std::string &rel) {
  const std::string what = where(root, rel);
  Walk w = walkToParent(root, rel);
  if (w.dfd < 0)
    ERR("'" << what << "': " << w.why)
  Fd dir(w.dfd);
  const std::string &leaf = w.parts.back();
  struct stat st;
  if (::fstatat(dir.fd, leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0)
    ERR("'" << what << "': " << ::strerror(errno))
  if (S_ISDIR(st.st_mode))
    ERR("'" << what << "' is a directory")
  if (::unlinkat(dir.fd, leaf.c_str(), 0) != 0)
    ERR("'" << what << "': unlink: " << ::strerror(errno))
}

void touch(const std::string &root, const std::string &rel, mode_t mode) {
  const std::string what = where(root, rel);
  Walk w = walkToParent(root, rel);
  if (w.dfd < 0)
    ERR("'" << what << "': " << w.why)
  Fd dir(w.dfd);
  const std::string &leaf = w.parts.back();
  struct stat st;
  if (::fstatat(dir.fd, leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
    if (!S_ISREG(st.st_mode))
      ERR("'" << what << "' is not a regular file (a symlink, directory or socket left in the jail?)")
    return;
  }
  Fd f(::openat(dir.fd, leaf.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode));
  if (f.fd < 0)
    ERR("'" << what << "': " << reason(dir.fd, leaf, errno))
  closeChecked(f, what);
}

int openDirectory(const std::string &root, const std::string &rel) {
  if (rel.find_first_not_of('/') == std::string::npos) {
    int fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
      ERR("'" << root << "': " << ::strerror(errno))
    return fd;
  }
  const std::string what = where(root, rel);
  Walk w = walkToParent(root, rel);
  if (w.dfd < 0)
    ERR("'" << what << "': " << w.why)
  Fd dir(w.dfd);
  const std::string &leaf = w.parts.back();
  int fd = ::openat(dir.fd, leaf.c_str(), kDirFlags);
  if (fd < 0)
    ERR("'" << what << "': " << reason(dir.fd, leaf, errno))
  return fd;
}

dev_t parentDevice(const std::string &root, const std::string &rel) {
  Walk w = walkToParent(root, rel);
  if (w.dfd < 0)
    ERR("'" << where(root, rel) << "': " << w.why)
  Fd dir(w.dfd);
  struct stat st;
  if (::fstat(dir.fd, &st) != 0)
    ERR("'" << where(root, rel) << "': fstat: " << ::strerror(errno))
  return st.st_dev;
}

void linkIn(const std::string &hostSrc, const std::string &root, const std::string &rel) {
  const std::string what = where(root, rel);
  Walk w = walkToParent(root, rel);
  if (w.dfd < 0)
    ERR("'" << what << "': " << w.why)
  Fd dir(w.dfd);
  if (::linkat(AT_FDCWD, hostSrc.c_str(), dir.fd, w.parts.back().c_str(), AT_SYMLINK_FOLLOW) != 0)
    ERR("link '" << hostSrc << "' -> '" << what << "': " << ::strerror(errno))
}

void linkOut(const std::string &root, const std::string &rel, const std::string &hostDst) {
  const std::string what = where(root, rel);
  Walk w = walkToParent(root, rel);
  if (w.dfd < 0)
    ERR("'" << what << "': " << w.why)
  Fd dir(w.dfd);
  const std::string &leaf = w.parts.back();
  struct stat st;
  if (::fstatat(dir.fd, leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0)
    ERR("'" << what << "': " << ::strerror(errno))
  if (!S_ISREG(st.st_mode))
    ERR("'" << what << "' is not a regular file")
  // flags 0: the name itself is linked, a symlink is never followed
  if (::linkat(dir.fd, leaf.c_str(), AT_FDCWD, hostDst.c_str(), 0) != 0)
    ERR("link '" << what << "' -> '" << hostDst << "': " << ::strerror(errno))
  struct stat lt;
  if (::lstat(hostDst.c_str(), &lt) != 0 || !S_ISREG(lt.st_mode) ||
      lt.st_ino != st.st_ino || lt.st_dev != st.st_dev) {
    (void)::unlink(hostDst.c_str());
    ERR("'" << what << "' changed while it was linked to '" << hostDst << "' — link removed")
  }
}

void mkdirs(const std::string &root, const std::string &rel, mode_t mode) {
  const std::string what = where(root, rel);
  Walk w = walkToParent(root, rel, mode);
  if (w.dfd < 0)
    ERR("'" << what << "': " << w.why)
  Fd dir(w.dfd);
  const std::string &leaf = w.parts.back();
  if (::mkdirat(dir.fd, leaf.c_str(), mode) != 0 && errno != EEXIST)
    ERR("'" << what << "': mkdir: " << ::strerror(errno))
  int fd = ::openat(dir.fd, leaf.c_str(), kDirFlags);
  if (fd < 0)
    ERR("'" << what << "': " << reason(dir.fd, leaf, errno))
  ::close(fd);
}

}
