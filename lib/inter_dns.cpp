// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "inter_dns.h"
#include "inter_dns_pure.h"

#include "args.h"
#include "commands.h"
#include "jail_query.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>
#include <iostream>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <vector>

namespace InterDns {

namespace {

std::string readFileIfExists(const std::string &path) {
  std::ifstream f(path);
  if (!f.is_open()) return "";
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

void atomicWrite(const std::string &path, const std::string &content) {
  // Write to <path>.tmp.<pid> then rename — survives crashes mid-write.
  auto tmp = path + ".tmp." + std::to_string(::getpid());
  int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) ERR2("inter-dns", "open '" << tmp << "' failed: " << strerror(errno));
  size_t off = 0;
  while (off < content.size()) {
    ssize_t n = ::write(fd, content.data() + off, content.size() - off);
    if (n <= 0) {
      ::close(fd);
      ::unlink(tmp.c_str());
      ERR2("inter-dns", "write '" << tmp << "' failed: " << strerror(errno));
    }
    off += (size_t)n;
  }
  ::close(fd);
  if (::rename(tmp.c_str(), path.c_str()) != 0) {
    ::unlink(tmp.c_str());
    ERR2("inter-dns", "rename '" << tmp << "' -> '" << path << "' failed: " << strerror(errno));
  }
}

bool tryReloadUnbound() {
  // unbound-control reload is the cheap path; service reload is the
  // fallback if the control channel isn't configured.
  try {
    Util::execCommand({"/usr/local/sbin/unbound-control", "reload"},
                      "reload unbound");
    return true;
  } catch (...) {}
  try {
    Util::execCommand({"/usr/sbin/service", "unbound", "reload"},
                      "reload unbound (service)");
    return true;
  } catch (...) {}
  return false;
}

std::vector<InterDnsPure::Entry> collectEntries() {
  std::vector<InterDnsPure::Entry> entries;
  for (auto &j : JailQuery::getAllJails(true /*crateOnly*/)) {
    if (j.dying) continue;
    if (!InterDnsPure::validateHostname(j.name).empty()) continue;
    InterDnsPure::Entry e;
    e.name = j.name;
    e.ip4  = j.ip4;
    // Jail v6 isn't surfaced by JailInfo today; left empty.
    entries.push_back(std::move(e));
  }
  return entries;
}

} // anon

RebuildResult rebuild(const std::string &hostsPath,
                      const std::string &unboundPath,
                      bool reloadUnbound) {
  RebuildResult r;
  r.hostsPath = hostsPath;
  r.unboundPath = unboundPath;

  auto entries = collectEntries();
  r.entries = (unsigned)entries.size();

  if (!hostsPath.empty()) {
    auto block = InterDnsPure::buildHostsBlock(entries);
    auto existing = readFileIfExists(hostsPath);
    auto merged = InterDnsPure::replaceHostsBlock(existing, block);
    atomicWrite(hostsPath, merged);
    r.wroteHosts = true;
  }

  if (!unboundPath.empty()) {
    auto fragment = InterDnsPure::buildUnboundFragment(entries);
    atomicWrite(unboundPath, fragment);
    r.wroteUnbound = true;
    if (reloadUnbound)
      r.reloadedUnbound = tryReloadUnbound();
  }

  return r;
}

} // namespace InterDns

// CLI command entry point — wired from cli/main.cpp via commands.h.
bool interDnsCommand(const Args &/*args*/) {
  auto r = InterDns::rebuild();
  std::cout << rang::fg::green
            << "inter-dns: " << r.entries << " entries"
            << " (hosts=" << r.hostsPath
            << " unbound=" << r.unboundPath
            << " reloaded=" << (r.reloadedUnbound ? "yes" : "no") << ")"
            << rang::style::reset << std::endl;
  return true;
}
