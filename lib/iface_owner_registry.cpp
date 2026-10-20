// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "iface_owner_registry.h"

#include <cerrno>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

namespace {

bool slurp(const std::string &path, std::string &out) {
  std::ifstream f(path, std::ios::binary);
  if (!f.is_open()) return false;
  std::ostringstream buf;
  buf << f.rdbuf();
  out = buf.str();
  return true;
}

} // namespace

IfaceOwnerRegistry::IfaceOwnerRegistry(std::string path) : path_(std::move(path)) {
  std::string text;
  if (!slurp(path_, text)) return;
  std::string err;
  if (!IfaceOwnerRegistryPure::parse(text, entries_, err))
    throw std::runtime_error("iface_owner_registry: " + path_ + ": " + err);
}

void IfaceOwnerRegistry::recordEpair(const std::string &ifaceA,
                                     const std::string &ifaceB, uint32_t uid) {
  std::lock_guard<std::mutex> g(m_);
  if (IfaceOwnerRegistryPure::isEpairName(ifaceA)) entries_[ifaceA] = uid;
  if (IfaceOwnerRegistryPure::isEpairName(ifaceB)) entries_[ifaceB] = uid;
  persistLocked_();
}

bool IfaceOwnerRegistry::forgetPair(const std::string &ifname) {
  std::lock_guard<std::mutex> g(m_);
  size_t n = entries_.erase(ifname);
  const std::string peer = IfaceOwnerRegistryPure::peerHalf(ifname);
  if (!peer.empty()) n += entries_.erase(peer);
  if (n) persistLocked_();
  return n != 0;
}

void IfaceOwnerRegistry::setLiveProbe(IfaceOwnerRegistryPure::LiveProbe probe) {
  std::lock_guard<std::mutex> g(m_);
  probe_ = std::move(probe);
}

size_t IfaceOwnerRegistry::reconcile() {
  std::lock_guard<std::mutex> g(m_);
  if (!probe_) return 0;
  size_t dropped = IfaceOwnerRegistryPure::reconcile(entries_, probe_);
  if (dropped) persistLocked_();
  return dropped;
}

bool IfaceOwnerRegistry::dropIfStaleLocked_(
    IfaceOwnerRegistryPure::EntryMap::iterator it) const {
  if (!probe_) return false;
  const std::string probe = IfaceOwnerRegistryPure::hostHalf(it->first);
  if (!probe.empty() && probe_(probe)) return false;
  auto &self = const_cast<IfaceOwnerRegistry &>(*this);
  const std::string peer = IfaceOwnerRegistryPure::peerHalf(it->first);
  self.entries_.erase(it);
  if (!peer.empty()) self.entries_.erase(peer);
  try { persistLocked_(); } catch (...) { /* best-effort bookkeeping */ }
  return true;
}

PrivOpsAuthzPure::Owner IfaceOwnerRegistry::lookup(const std::string &ifname) const {
  std::lock_guard<std::mutex> g(m_);
  PrivOpsAuthzPure::Owner o;
  auto &self = const_cast<IfaceOwnerRegistry &>(*this);
  auto it = self.entries_.find(ifname);
  if (it != self.entries_.end()) {
    uint32_t uid = it->second;
    if (!dropIfStaleLocked_(it)) {
      o.known = true;
      o.uid   = uid;
    }
  }
  return o;
}

size_t IfaceOwnerRegistry::size() const {
  std::lock_guard<std::mutex> g(m_);
  return entries_.size();
}

void IfaceOwnerRegistry::persistLocked_() const {
  std::string tmp = path_ + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f.is_open())
      throw std::runtime_error("iface_owner_registry: cannot open " + tmp);
    f << IfaceOwnerRegistryPure::serialize(entries_);
    if (!f.good())
      throw std::runtime_error("iface_owner_registry: write failed for " + tmp);
  }
  if (::rename(tmp.c_str(), path_.c_str()) != 0) {
    int e = errno;
    ::unlink(tmp.c_str());
    throw std::runtime_error("iface_owner_registry: rename to " + path_ +
                             " failed: " + std::to_string(e));
  }
}
