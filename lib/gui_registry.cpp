// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "gui_registry.h"

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <iostream>
#include <sstream>
#include <set>

#include "util.h"
#include "err.h"
#include <rang.hpp>
#include "locs.h"

#define ERR(msg...) ERR2("gui registry", msg)

namespace Ctx {

GuiRegistry::GuiRegistry()
: fd(-1), inMemory(false), changed(false)
{ }

GuiRegistry::~GuiRegistry() {
  if (fd != -1)
    WARN("GuiRegistry: closing file on destructor: " << file())
  if (fd != -1 && ::close(fd) == -1)
    WARN("GuiRegistry: unable to close the file " << file() << ": " << strerror(errno))
}

std::unique_ptr<GuiRegistry> GuiRegistry::lock() {
  auto ctx = std::make_unique<GuiRegistry>();
  ctx->fd = ::open(file().c_str(), O_RDWR|O_CREAT|O_EXLOCK, 0600);
  if (ctx->fd == -1)
    ERR("failed to open file " << file() << ": " << strerror(errno))
  return ctx;
}

void GuiRegistry::unlock() {
  if (changed)
    writeToFile();
  if (::close(fd) == -1) {
    fd = -1;
    ERR("failed to close file " << file() << ": " << strerror(errno))
  }
  fd = -1;
}

unsigned GuiRegistry::allocateDisplay(pid_t ownerPid) {
  if (!inMemory)
    readIntoMemory();
  garbageCollect();
  // find the lowest unused display number starting from 10
  std::set<unsigned> usedDisplays;
  for (auto &kv : entries)
    usedDisplays.insert(kv.second.displayNum);
  unsigned disp = 10;
  while (usedDisplays.count(disp))
    disp++;
  return disp;
}

void GuiRegistry::registerEntry(const GuiEntry &entry) {
  if (!inMemory)
    readIntoMemory();
  garbageCollect();
  entries[entry.ownerPid] = entry;
  changed = true;
}

void GuiRegistry::unregisterEntry(pid_t ownerPid) {
  if (!inMemory)
    readIntoMemory();
  entries.erase(ownerPid);
  changed = true;
}

std::vector<GuiEntry> GuiRegistry::getEntries() {
  if (!inMemory)
    readIntoMemory();
  garbageCollect();
  std::vector<GuiEntry> result;
  for (auto &kv : entries)
    result.push_back(kv.second);
  return result;
}

const GuiEntry* GuiRegistry::findByTarget(const std::string &target) const {
  // Priority: exact jail name > partial jail name > display number > owner PID.
  // Multi-pass to avoid numeric ambiguity (a PID could collide with a display number).
  for (auto &kv : entries)
    if (kv.second.jailName == target)
      return &kv.second;
  for (auto &kv : entries)
    if (kv.second.jailName.find("jail-" + target) == 0)
      return &kv.second;
  // Numeric lookup: try display number first, then PID
  try {
    int num = std::stoi(target);
    for (auto &kv : entries)
      if ((int)kv.second.displayNum == num)
        return &kv.second;
    for (auto &kv : entries)
      if ((int)kv.second.ownerPid == num)
        return &kv.second;
  } catch (...) {}
  return nullptr;
}

std::string GuiRegistry::file() {
  return Locations::ctxGuiRegistryFilePath;
}

void GuiRegistry::readIntoMemory() {
  // format: "ownerPid displayNum xServerPid vncPort wsPort mode jailName\n"
  for (auto const &line : Util::Fs::readFileLines(fd)) {
    std::istringstream is(line);
    GuiEntry e;
    e.wsPort = 0;
    if (is >> e.ownerPid >> e.displayNum >> e.xServerPid >> e.vncPort >> e.wsPort >> e.mode >> e.jailName)
      entries[e.ownerPid] = e;
  }
  inMemory = true;
}

void GuiRegistry::writeToFile() const {
  std::ostringstream ss;
  for (auto &kv : entries) {
    auto &e = kv.second;
    ss << e.ownerPid << " " << e.displayNum << " " << e.xServerPid
       << " " << e.vncPort << " " << e.wsPort << " " << e.mode << " " << e.jailName << std::endl;
  }
  if (::ftruncate(fd, 0) == -1)
    ERR("failed to truncate file " << file() << ": " << strerror(errno) << " (fd=" << fd << ")")
  if (::lseek(fd, 0, SEEK_SET) == -1)
    ERR("failed to seek in file " << file() << ": " << strerror(errno) << " (fd=" << fd << ")")
  Util::Fs::writeFile(ss.str(), fd);
}

void GuiRegistry::garbageCollect() {
  auto it = entries.begin();
  while (it != entries.end()) {
    if (::kill(it->first, 0) == -1 && errno == ESRCH) {
      it = entries.erase(it); // owner PID doesn't exist
      changed = true;
    } else {
      ++it;
    }
  }
}

}
