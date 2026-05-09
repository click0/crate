// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "network_lease.h"
#include "privops_client.h"
#include "runtime_paths_pure.h"
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

#define ERR(msg...) ERR2("network-lease", msg)

namespace NetworkLease {

namespace {

// 0.9.27: legacy single-tenant default. The actual path used at
// runtime comes from `effectivePath()` below — when crated's
// privops socket is detected, the lease file moves under
// /var/run/crate/<uid>/network-leases.txt so each operator's
// IP allocations stay isolated. Tests + the explicit
// setPathForTesting() override route still use g_path directly.
std::string g_path = "/var/run/crate/network-leases.txt";
bool g_pathOverridden = false;  // set by setPathForTesting

// Resolve the lease file path. Lazily caches the per-uid path
// when rootless mode is active. Same path for the entire
// process lifetime.
const std::string &effectivePath() {
  static std::string cached;
  static bool computed = false;
  if (!computed) {
    if (g_pathOverridden) {
      cached = g_path;  // honour test override
    } else if (!PrivOpsClient::detectSocketPath().empty()) {
      cached = RuntimePathsPure::perUserRoot((uint32_t)::getuid())
             + "/network-leases.txt";
    } else {
      cached = g_path;  // legacy single-tenant
    }
    computed = true;
  }
  return cached;
}

// Open (creating) the lease file and acquire an exclusive lock.
// Returns the fd. Caller must ::close() it.
int openLocked() {
  int fd = ::open(effectivePath().c_str(),
                  O_RDWR | O_CREAT | O_CLOEXEC,
                  0640);
  if (fd < 0)
    ERR("cannot open "  << effectivePath() << ": " << std::strerror(errno))
  if (::flock(fd, LOCK_EX) != 0) {
    int e = errno;
    ::close(fd);
    ERR("flock "  << effectivePath() << ": " << std::strerror(e))
  }
  return fd;
}

// Read the whole locked fd into memory.
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

// Parse buffer into leases. Throws on syntax errors.
std::vector<IpAllocPure::Lease> parseAll(const std::string &buf) {
  std::vector<IpAllocPure::Lease> out;
  std::istringstream is(buf);
  std::string line;
  std::size_t lineNo = 0;
  while (std::getline(is, line)) {
    lineNo++;
    // Strip CR (in case of Windows-edited file).
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    IpAllocPure::Lease l;
    if (auto err = IpAllocPure::parseLeaseLine(line, l); !err.empty()) {
      ERR("line " << lineNo << ": " << err << " (line: '" << line << "')")
    }
    out.push_back(l);
  }
  return out;
}

// Atomically replace the lease file contents. Caller MUST hold the
// flock on `lockedFd`. Writes to a tmp file, fsync, rename — so
// crash mid-write doesn't leave a corrupt half-written file.
void writeAllAtomic(int /*lockedFd*/,
                    const std::vector<IpAllocPure::Lease> &leases) {
  std::string tmp = effectivePath() + ".tmp";
  int fd = ::open(tmp.c_str(),
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                  0640);
  if (fd < 0) ERR("open tmp " << tmp << ": " << std::strerror(errno))
  std::string out;
  out += "# crate network leases — managed by crate run / crate clean\n";
  out += "# format: <jail-name> <ip>\n";
  for (const auto &l : leases) {
    out += IpAllocPure::formatLeaseLine(l);
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
  if (::rename(tmp.c_str(), effectivePath().c_str()) != 0) {
    int e = errno;
    ::unlink(tmp.c_str());
    ERR("rename " << tmp << " -> "  << effectivePath() << ": " << std::strerror(e))
  }
}

} // anon

const std::string &leasePath() { return effectivePath(); }
void setPathForTesting(const std::string &path) {
  g_path = path;
  g_pathOverridden = true;
  // Note: effectivePath()'s static cache is computed on first
  // call, so for tests that exercise setPathForTesting after
  // effectivePath() has already cached, the override won't take
  // effect. Tests that need to swap paths mid-run should fork
  // (ATF tests already run in subprocesses), giving each test
  // its own first-call cache.
}

std::vector<IpAllocPure::Lease> readAll() {
  // Open without lock for read-only callers (e.g. `crate doctor`,
  // future). Tolerate ENOENT.
  int fd = ::open(effectivePath().c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    if (errno == ENOENT) return {};
    ERR("open "  << effectivePath() << ": " << std::strerror(errno))
  }
  auto buf = readAllFd(fd);
  ::close(fd);
  return parseAll(buf);
}

uint32_t allocateFor(const std::string &jail,
                     const IpAllocPure::Network &pool) {
  int fd = openLocked();
  // RAII close — but we don't have a scope guard; use a tiny inline
  // class.
  struct Closer { int f; ~Closer(){ if (f >= 0) ::close(f); } } c{fd};

  auto buf = readAllFd(fd);
  auto leases = parseAll(buf);

  // Idempotent: if jail already has a lease, return its IP.
  for (const auto &l : leases) {
    if (l.name == jail) return l.ip;
  }

  // Build taken list.
  std::vector<uint32_t> taken;
  taken.reserve(leases.size());
  for (const auto &l : leases) taken.push_back(l.ip);

  uint32_t addr = IpAllocPure::allocateNext(pool, taken);
  if (addr == 0)
    ERR("pool " << IpAllocPure::formatIp(pool.base) << "/" << pool.prefixLen
        << " exhausted (" << leases.size() << " leases active)")

  IpAllocPure::Lease n;
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
  std::vector<IpAllocPure::Lease> kept;
  kept.reserve(leases.size());
  for (const auto &l : leases) {
    if (l.name == jail) { changed = true; continue; }
    kept.push_back(l);
  }
  if (changed) writeAllAtomic(fd, kept);
}

} // namespace NetworkLease
