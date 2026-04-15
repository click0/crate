// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ctx.h"

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include <iostream>
#include <sstream>
#include <memory>
#include <signal.h>

#include "util.h"
#include "err.h"
#include "locs.h"

#define ERR(msg...) ERR2("managing context info", msg)

namespace Ctx {

FwUsers::FwUsers()
: fd(-1), inMemory(false), changed(false)
{ }

FwUsers::~FwUsers() {
  if (fd != -1)
    WARN("closing file on destructor: " << file())
  if (fd != -1 && ::close(fd) == -1) // unlock() wasn't called: must be an erorr condition
    WARN("unable to close the file " << file() << ": " << strerror(errno))
}

std::unique_ptr<FwUsers> FwUsers::lock() {
  auto ctx = std::make_unique<FwUsers>();
  // open and lock the file
  ctx->fd = ::open(file().c_str(), O_RDWR|O_CREAT|O_EXLOCK, 0600);
  if (ctx->fd == -1)
    ERR("failed to open file " << file() << ": " << strerror(errno))
  return ctx;
}

void FwUsers::unlock() {
  // write if the content has changed
  if (changed)
    writeToFile();
  // close
  if (::close(fd) == -1) {
    fd = -1;
    ERR("failed to close file " << file() << ": " << strerror(errno))
  }
  fd = -1;
}

bool FwUsers::isEmpty() const {
  if (inMemory)
    return pids.empty();
  else
    return Util::Fs::getFileSize(fd) == 0;
}

void FwUsers::add(pid_t pid) {
  if (inMemory) {
    pids.insert(int(pid));
    changed = true;
  } else {
    if (::lseek(fd, 0, SEEK_END) == -1)
      ERR("failed to seek in file " << file() << ": " << strerror(errno))
    Util::Fs::writeFile(STR(pid << std::endl), fd);
  }
}

void FwUsers::del(pid_t pid) {
  if (!inMemory)
    readIntoMemory();
  pids.erase(pids.find(pid));
  changed = true;
}

/// internals

std::string FwUsers::file() {
  return Locations::ctxFwUsersFilePath;
}

void FwUsers::readIntoMemory() {
  for (auto const &line : Util::Fs::readFileLines(fd)) {
    if (line.empty())
      continue;
    try {
      pids.insert(std::stoul(line));
    } catch (const std::exception &) {
      // Ignore malformed pid lines (stale/corrupted context file).
    }
  }
  inMemory = true;
}

void FwUsers::writeToFile() const {
  // form the file content
  std::ostringstream ss;
  for (auto pid : pids)
    ss << pid << std::endl;
  // write
  if (::ftruncate(fd, 0) == -1)
    ERR("failed to truncate file " << file() << ": " << strerror(errno) << " (fd=" << fd << ")")
  if (::lseek(fd, 0, SEEK_SET) == -1)
    ERR("failed to seek in file " << file() << ": " << strerror(errno) << " (fd=" << fd << ")")
  Util::Fs::writeFile(ss.str(), fd);
}

// ===== FwSlots (§18): Dynamic ipfw rule slot allocator =====

FwSlots::FwSlots()
: fd(-1), inMemory(false), changed(false)
{ }

FwSlots::~FwSlots() {
  if (fd != -1)
    WARN("FwSlots: closing file on destructor: " << file())
  if (fd != -1 && ::close(fd) == -1)
    WARN("FwSlots: unable to close the file " << file() << ": " << strerror(errno))
}

std::unique_ptr<FwSlots> FwSlots::lock() {
  auto ctx = std::make_unique<FwSlots>();
  ctx->fd = ::open(file().c_str(), O_RDWR|O_CREAT|O_EXLOCK, 0600);
  if (ctx->fd == -1)
    ERR("failed to open file " << file() << ": " << strerror(errno))
  return ctx;
}

void FwSlots::unlock() {
  if (changed)
    writeToFile();
  if (::close(fd) == -1) {
    fd = -1;
    ERR("failed to close file " << file() << ": " << strerror(errno))
  }
  fd = -1;
}

unsigned FwSlots::allocate(pid_t pid) {
  if (!inMemory)
    readIntoMemory();
  garbageCollect();
  // find the lowest unused slot number
  std::set<unsigned> usedSlots;
  for (auto &kv : slots)
    usedSlots.insert(kv.second);
  unsigned slot = 0;
  while (usedSlots.count(slot))
    slot++;
  slots[pid] = slot;
  changed = true;
  return slot;
}

void FwSlots::release(pid_t pid) {
  if (!inMemory)
    readIntoMemory();
  slots.erase(pid);
  changed = true;
}

std::string FwSlots::file() {
  return std::string(Locations::jailDirectoryPath) + "/ctx-fw-slots";
}

void FwSlots::readIntoMemory() {
  for (auto const &line : Util::Fs::readFileLines(fd)) {
    // format: "pid slot\n"
    std::istringstream is(line);
    pid_t pid;
    unsigned slot;
    if (is >> pid >> slot)
      slots[pid] = slot;
  }
  inMemory = true;
}

void FwSlots::writeToFile() const {
  std::ostringstream ss;
  for (auto &kv : slots)
    ss << kv.first << " " << kv.second << std::endl;
  if (::ftruncate(fd, 0) == -1)
    ERR("failed to truncate file " << file() << ": " << strerror(errno) << " (fd=" << fd << ")")
  if (::lseek(fd, 0, SEEK_SET) == -1)
    ERR("failed to seek in file " << file() << ": " << strerror(errno) << " (fd=" << fd << ")")
  Util::Fs::writeFile(ss.str(), fd);
}

void FwSlots::garbageCollect() {
  // Remove entries for PIDs that no longer exist
  auto it = slots.begin();
  while (it != slots.end()) {
    if (::kill(it->first, 0) == -1 && errno == ESRCH)
      it = slots.erase(it); // PID doesn't exist
    else
      ++it;
  }
}

}
