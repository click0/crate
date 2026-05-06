// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "network_lease6.h"
#include "err.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>

#define ERR(msg...) ERR2("network-lease6", msg)

namespace NetworkLease6 {

namespace {

std::string g_path = "/var/run/crate/network-leases6.txt";

int openLocked() {
  int fd = ::open(g_path.c_str(),
                  O_RDWR | O_CREAT | O_CLOEXEC,
                  0640);
  if (fd < 0)
    ERR("cannot open " << g_path << ": " << std::strerror(errno))
  if (::flock(fd, LOCK_EX) != 0) {
    int e = errno;
    ::close(fd);
    ERR("flock " << g_path << ": " << std::strerror(e))
  }
  return fd;
}

std::string readAllFd(int fd) {
  if (::lseek(fd, 0, SEEK_SET) < 0)
    ERR("lseek: " << std::strerror(errno))
  std::string buf;
  char tmp[4096];
  while (true) {
    ssize_t n = ::read(fd, tmp, sizeof(tmp));
    if (n < 0) ERR("read: " << std::strerror(errno))
    if (n == 0) break;
    buf.append(tmp, (std::size_t)n);
  }
  return buf;
}

std::vector<Ip6AllocPure::Lease6> parseAll(const std::string &buf) {
  std::vector<Ip6AllocPure::Lease6> out;
  std::istringstream is(buf);
  std::string line;
  std::size_t lineNo = 0;
  while (std::getline(is, line)) {
    lineNo++;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    Ip6AllocPure::Lease6 l;
    if (auto err = Ip6AllocPure::parseLeaseLine6(line, l); !err.empty()) {
      ERR("line " << lineNo << ": " << err << " (line: '" << line << "')")
    }
    out.push_back(l);
  }
  return out;
}

void writeAllAtomic(int /*lockedFd*/,
                    const std::vector<Ip6AllocPure::Lease6> &leases) {
  std::string tmp = g_path + ".tmp";
  int fd = ::open(tmp.c_str(),
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                  0640);
  if (fd < 0) ERR("open tmp " << tmp << ": " << std::strerror(errno))
  std::string out;
  out += "# crate IPv6 leases — managed by crate run / crate clean\n";
  out += "# format: <jail-name> <ip6>\n";
  for (const auto &l : leases) {
    out += Ip6AllocPure::formatLeaseLine6(l);
    out += '\n';
  }
  std::size_t off = 0;
  while (off < out.size()) {
    ssize_t n = ::write(fd, out.data() + off, out.size() - off);
    if (n < 0) {
      int e = errno;
      ::close(fd); ::unlink(tmp.c_str());
      ERR("write tmp: " << std::strerror(e))
    }
    off += (std::size_t)n;
  }
  ::fsync(fd);
  ::close(fd);
  if (::rename(tmp.c_str(), g_path.c_str()) != 0) {
    int e = errno;
    ::unlink(tmp.c_str());
    ERR("rename " << tmp << " -> " << g_path << ": " << std::strerror(e))
  }
}

} // anon

const std::string &leasePath() { return g_path; }
void setPathForTesting(const std::string &path) { g_path = path; }

std::vector<Ip6AllocPure::Lease6> readAll() {
  int fd = ::open(g_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    if (errno == ENOENT) return {};
    ERR("open " << g_path << ": " << std::strerror(errno))
  }
  auto buf = readAllFd(fd);
  ::close(fd);
  return parseAll(buf);
}

Ip6AllocPure::Addr6 allocateFor(const std::string &jail,
                                const Ip6AllocPure::Network6 &pool) {
  int fd = openLocked();
  struct Closer { int f; ~Closer(){ if (f >= 0) ::close(f); } } c{fd};

  auto buf = readAllFd(fd);
  auto leases = parseAll(buf);

  // Idempotent: existing jail keeps its IP.
  for (const auto &l : leases) {
    if (l.name == jail) return l.ip;
  }

  std::vector<Ip6AllocPure::Addr6> taken;
  taken.reserve(leases.size());
  for (const auto &l : leases) taken.push_back(l.ip);

  auto addr = Ip6AllocPure::allocateNext(pool, taken);
  bool zero = true;
  for (auto b : addr) if (b != 0) { zero = false; break; }
  if (zero)
    ERR("IPv6 pool " << Ip6AllocPure::formatIp6(pool.base) << "/" << pool.prefixLen
        << " exhausted (" << leases.size() << " leases active)")

  Ip6AllocPure::Lease6 n;
  n.name = jail;
  n.ip   = addr;
  leases.push_back(n);
  writeAllAtomic(fd, leases);
  return addr;
}

void releaseFor(const std::string &jail) {
  int fd = openLocked();
  struct Closer { int f; ~Closer(){ if (f >= 0) ::close(f); } } c{fd};

  auto buf = readAllFd(fd);
  auto leases = parseAll(buf);

  bool changed = false;
  std::vector<Ip6AllocPure::Lease6> kept;
  kept.reserve(leases.size());
  for (const auto &l : leases) {
    if (l.name == jail) { changed = true; continue; }
    kept.push_back(l);
  }
  if (changed) writeAllAtomic(fd, kept);
}

} // namespace NetworkLease6
