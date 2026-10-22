// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "fw_lease_registry.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

namespace {

const char kSysctl4[] = "net.inet.ip.forwarding";
const char kSysctl6[] = "net.inet6.ip6.forwarding";

bool slurp(const std::string &path, std::string &out) {
  std::ifstream f(path, std::ios::binary);
  if (!f.is_open()) return false;
  std::ostringstream buf;
  buf << f.rdbuf();
  out = buf.str();
  return true;
}

} // namespace

FwLeaseRegistry::FwLeaseRegistry(std::string path, SysctlIo io)
  : path_(std::move(path)), io_(std::move(io)) {
  std::string text;
  if (!slurp(path_, text)) return;
  std::string err;
  if (!FwLeasePure::parse(text, state_, err))
    throw std::runtime_error("fw_lease_registry: " + path_ + ": " + err);
}

std::string FwLeaseRegistry::acquire(unsigned jid, bool wantSlot, bool want4, bool want6,
                                     Result &out) {
  std::lock_guard<std::mutex> g(m_);
  FwLeasePure::Entry e;
  FwLeasePure::Transition t;
  std::string err;
  if (!FwLeasePure::acquire(state_, jid, wantSlot, want4, want6, e, t, err))
    return err;
  applyTransitionLocked_(t);
  persistLocked_();
  auto c = FwLeasePure::counts(state_);
  out.slot = e.slot;
  out.fwd4Users = c.fwd4;
  out.fwd6Users = c.fwd6;
  out.released = false;
  return "";
}

FwLeaseRegistry::Result FwLeaseRegistry::release(unsigned jid) {
  std::lock_guard<std::mutex> g(m_);
  bool found = false;
  auto t = FwLeasePure::release(state_, jid, found);
  if (found) {
    applyTransitionLocked_(t);
    persistLocked_();
  }
  auto c = FwLeasePure::counts(state_);
  Result r;
  r.released = found;
  r.fwd4Users = c.fwd4;
  r.fwd6Users = c.fwd6;
  return r;
}

void FwLeaseRegistry::setLiveProbe(std::function<bool(unsigned)> probe) {
  std::lock_guard<std::mutex> g(m_);
  probe_ = std::move(probe);
}

size_t FwLeaseRegistry::reconcile() {
  std::lock_guard<std::mutex> g(m_);
  if (!probe_) return 0;
  size_t dropped = 0;
  auto t = FwLeasePure::reconcile(state_, probe_, dropped);
  if (dropped) {
    applyTransitionLocked_(t);
    persistLocked_();
  }
  return dropped;
}

size_t FwLeaseRegistry::size() const {
  std::lock_guard<std::mutex> g(m_);
  return state_.leases.size();
}

// first: remember the value we found and switch on if needed; last:
// restore only what we changed. Sysctl failures are reported, never
// thrown — the lease bookkeeping must stay consistent with the file.
void FwLeaseRegistry::applyTransitionLocked_(const FwLeasePure::Transition &t) {
  auto flip = [this](const char *name, bool first, bool last, int &orig) {
    try {
      if (first) {
        int cur = io_.get ? io_.get(name) : 1;
        if (cur == 0 && io_.set) { io_.set(name, 1); orig = 0; }
        else orig = -1;
      } else if (last) {
        if (orig == 0 && io_.set) io_.set(name, 0);
        orig = -1;
      }
    } catch (const std::exception &e) {
      std::cerr << "crated: fw_lease_registry: " << name << ": " << e.what() << std::endl;
    }
  };
  flip(kSysctl4, t.first4, t.last4, state_.orig4);
  flip(kSysctl6, t.first6, t.last6, state_.orig6);
}

void FwLeaseRegistry::persistLocked_() const {
  std::string tmp = path_ + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f.is_open())
      throw std::runtime_error("fw_lease_registry: cannot write " + tmp);
    f << FwLeasePure::serialize(state_);
    f.flush();
    if (!f.good())
      throw std::runtime_error("fw_lease_registry: short write to " + tmp);
  }
  if (std::rename(tmp.c_str(), path_.c_str()) != 0) {
    ::unlink(tmp.c_str());
    throw std::runtime_error("fw_lease_registry: rename " + tmp + " -> " + path_ + " failed");
  }
}
