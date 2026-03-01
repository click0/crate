// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "collector.h"
#include "mib.h"

#include "gui_registry.h"
#include "util.h"

#include <sstream>

namespace CrateSnmp {

unsigned Collector::runningCount() const {
  unsigned n = 0;
  for (auto &c : containers_)
    if (c.state == 1)
      n++;
  return n;
}

void Collector::collect() {
  containers_.clear();

  // 1. Get running jails from jls
  try {
    auto output = Util::execCommandGetOutput(
      {"/usr/sbin/jls", "-q", "jid", "name", "dying"}, "jls");
    std::istringstream is(output);
    std::string jid, name, dying;
    while (is >> jid >> name >> dying) {
      ContainerMetrics m;
      m.name = name;
      m.jid = std::stoi(jid);
      m.state = (dying == "0") ? 1 : 3;
      containers_.push_back(m);
    }
  } catch (...) {}

  // 2. Get resource usage via rctl (if available)
  for (auto &c : containers_) {
    try {
      auto rctlOut = Util::execCommandGetOutput(
        {"/usr/bin/rctl", "-u", "jail:" + c.name}, "rctl");
      std::istringstream is(rctlOut);
      std::string line;
      while (std::getline(is, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        auto key = line.substr(0, eq);
        auto val = line.substr(eq + 1);
        if (key == "pcpu")
          c.cpuPct = std::stoi(val);
        else if (key == "memoryuse")
          c.memKB = std::stoull(val) / 1024;
      }
    } catch (...) {}
  }

  // 3. Merge GUI registry data
  try {
    auto reg = Ctx::GuiRegistry::lock();
    auto entries = reg->getEntries();
    reg->unlock();
    for (auto &gui : entries) {
      for (auto &c : containers_) {
        if (c.name == gui.jailName || gui.jailName.find("jail-" + c.name) == 0) {
          c.vncPort = gui.vncPort;
          c.wsPort = gui.wsPort;
          c.guiMode = gui.mode;
          break;
        }
      }
    }
  } catch (...) {}
}

void Collector::checkTraps() {
  for (auto &c : containers_) {
    auto it = prevStates_.find(c.name);
    if (it == prevStates_.end()) {
      // New container — send started trap if running
      if (c.state == 1)
        sendTrap(TrapType::ContainerStarted, c.name, c.jid);
    } else if (it->second != c.state) {
      if (c.state == 1)
        sendTrap(TrapType::ContainerStarted, c.name, c.jid);
      else if (c.state == 0 || c.state == 3)
        sendTrap(TrapType::ContainerStopped, c.name, c.jid);
    }
  }

  // Check for containers that disappeared (stopped)
  for (auto &prev : prevStates_) {
    bool found = false;
    for (auto &c : containers_)
      if (c.name == prev.first) { found = true; break; }
    if (!found)
      sendTrap(TrapType::ContainerStopped, prev.first, 0);
  }

  // Update previous states
  prevStates_.clear();
  for (auto &c : containers_)
    prevStates_[c.name] = c.state;
}

}
