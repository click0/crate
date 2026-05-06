// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "spec_registry.h"
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

#define ERR(msg...) ERR2("spec-registry", msg)

namespace SpecRegistry {

namespace {

std::string g_path = "/var/run/crate/spec-registry.txt";

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

std::vector<SpecRegistryPure::Entry> parseAll(const std::string &buf) {
  std::vector<SpecRegistryPure::Entry> out;
  std::istringstream is(buf);
  std::string line;
  std::size_t lineNo = 0;
  while (std::getline(is, line)) {
    lineNo++;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    SpecRegistryPure::Entry e;
    if (auto err = SpecRegistryPure::parseLine(line, e); !err.empty()) {
      ERR("line " << lineNo << ": " << err << " (line: '" << line << "')")
    }
    out.push_back(e);
  }
  return out;
}

void writeAllAtomic(int /*lockedFd*/,
                    const std::vector<SpecRegistryPure::Entry> &entries) {
  std::string tmp = g_path + ".tmp";
  int fd = ::open(tmp.c_str(),
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                  0640);
  if (fd < 0) ERR("open tmp " << tmp << ": " << std::strerror(errno))
  std::string out;
  out += "# crate spec registry — managed by `crate run -f`\n";
  out += "# format: <jail-name> <abs-crate-path>\n";
  for (const auto &e : entries) {
    out += SpecRegistryPure::formatLine(e);
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

const std::string &registryPath() { return g_path; }
void setPathForTesting(const std::string &p) { g_path = p; }

std::vector<SpecRegistryPure::Entry> readAll() {
  int fd = ::open(g_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    if (errno == ENOENT) return {};
    ERR("open " << g_path << ": " << std::strerror(errno))
  }
  auto buf = readAllFd(fd);
  ::close(fd);
  return parseAll(buf);
}

void upsert(const std::string &name, const std::string &cratePath) {
  SpecRegistryPure::Entry candidate{name, cratePath};
  if (auto err = SpecRegistryPure::validateEntry(candidate); !err.empty())
    ERR(err)

  int fd = openLocked();
  struct Closer { int f; ~Closer(){ if (f >= 0) ::close(f); } } c{fd};

  auto buf = readAllFd(fd);
  auto entries = parseAll(buf);

  int idx = SpecRegistryPure::findIndex(entries, name);
  if (idx >= 0) {
    if (entries[idx].cratePath == cratePath) return;   // idempotent no-op
    entries[idx].cratePath = cratePath;
  } else {
    entries.push_back(candidate);
  }
  writeAllAtomic(fd, entries);
}

void remove(const std::string &name) {
  int fd = openLocked();
  struct Closer { int f; ~Closer(){ if (f >= 0) ::close(f); } } c{fd};

  auto buf = readAllFd(fd);
  auto entries = parseAll(buf);
  bool changed = false;
  std::vector<SpecRegistryPure::Entry> kept;
  kept.reserve(entries.size());
  for (const auto &e : entries) {
    if (e.name == name) { changed = true; continue; }
    kept.push_back(e);
  }
  if (changed) writeAllAtomic(fd, kept);
}

std::string lookup(const std::string &name) {
  for (const auto &e : readAll())
    if (e.name == name) return e.cratePath;
  return "";
}

} // namespace SpecRegistry
