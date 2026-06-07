// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "jid_owner_registry.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace {

// Read entire file. Throws on read error other than ENOENT (which is
// "no file yet" -> empty registry, valid).
bool slurp(const std::string &path, std::string &out) {
  std::ifstream f(path, std::ios::binary);
  if (!f.is_open()) return false;     // missing file is fine
  std::ostringstream buf;
  buf << f.rdbuf();
  out = buf.str();
  return true;
}

} // namespace

JidOwnerRegistry::JidOwnerRegistry(std::string path) : path_(std::move(path)) {
  std::string text;
  if (!slurp(path_, text)) return;    // file doesn't exist -> empty registry
  std::string err;
  if (!JidOwnerRegistryPure::parse(text, entries_, err))
    throw std::runtime_error("jid_owner_registry: " + path_ + ": " + err);
}

void JidOwnerRegistry::recordCreate(unsigned jid, uint32_t uid,
                                    const std::string &name,
                                    const std::string &path) {
  std::lock_guard<std::mutex> g(m_);
  JidOwnerRegistryPure::Entry e;
  e.uid  = uid;
  e.name = name;
  e.path = path;
  entries_[jid] = std::move(e);       // replaces if present (idempotent)
  persistLocked_();
}

bool JidOwnerRegistry::forgetByJid(unsigned jid) {
  std::lock_guard<std::mutex> g(m_);
  auto it = entries_.find(jid);
  if (it == entries_.end()) return false;
  entries_.erase(it);
  persistLocked_();
  return true;
}

bool JidOwnerRegistry::forgetByName(const std::string &name) {
  std::lock_guard<std::mutex> g(m_);
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if (it->second.name == name) {
      entries_.erase(it);
      persistLocked_();
      return true;
    }
  }
  return false;
}

PrivOpsAuthzPure::Owner JidOwnerRegistry::lookupByJid(unsigned jid) const {
  std::lock_guard<std::mutex> g(m_);
  PrivOpsAuthzPure::Owner o;
  auto it = entries_.find(jid);
  if (it != entries_.end()) {
    o.known = true;
    o.uid   = it->second.uid;
  }
  return o;
}

PrivOpsAuthzPure::Owner JidOwnerRegistry::lookupByName(const std::string &name) const {
  std::lock_guard<std::mutex> g(m_);
  PrivOpsAuthzPure::Owner o;
  unsigned jid; JidOwnerRegistryPure::Entry e;
  if (JidOwnerRegistryPure::lookupByName(entries_, name, jid, e)) {
    o.known = true;
    o.uid   = e.uid;
  }
  return o;
}

PrivOpsAuthzPure::Owner JidOwnerRegistry::lookupByPath(const std::string &path) const {
  std::lock_guard<std::mutex> g(m_);
  PrivOpsAuthzPure::Owner o;
  unsigned jid; JidOwnerRegistryPure::Entry e;
  if (JidOwnerRegistryPure::findOwnerByPath(entries_, path, jid, e)) {
    o.known = true;
    o.uid   = e.uid;
  }
  return o;
}

PrivOpsAuthzPure::OwnerLookup JidOwnerRegistry::makeLookup() const {
  PrivOpsAuthzPure::OwnerLookup l;
  // Capture by-ref: the registry outlives the dispatcher (held by main).
  l.byJid  = [this](unsigned jid)            { return this->lookupByJid(jid); };
  l.byName = [this](const std::string &name) { return this->lookupByName(name); };
  l.byPath = [this](const std::string &path) { return this->lookupByPath(path); };
  return l;
}

size_t JidOwnerRegistry::size() const {
  std::lock_guard<std::mutex> g(m_);
  return entries_.size();
}

void JidOwnerRegistry::persistLocked_() const {
  // Atomic write: tmpfile + rename. A torn fsync of the tmp file is
  // fine — the live file is only swapped after the tmp is fully written.
  std::string tmp = path_ + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f.is_open())
      throw std::runtime_error("jid_owner_registry: cannot open " + tmp);
    f << JidOwnerRegistryPure::serialize(entries_);
    if (!f.good())
      throw std::runtime_error("jid_owner_registry: write failed for " + tmp);
  }
  if (::rename(tmp.c_str(), path_.c_str()) != 0) {
    int e = errno;
    ::unlink(tmp.c_str());
    throw std::runtime_error("jid_owner_registry: rename to " + path_ +
                             " failed: " + std::to_string(e));
  }
}
