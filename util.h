// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#pragma once

#include <string>
#include <vector>
#include <set>
#include <iostream>
#include <sstream>
#include <memory>
#include <functional>

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include <rang.hpp>

//
// utility macros useful throughout the program
//

#define STR(msg...) \
  ([&]() { \
    std::ostringstream ss; \
    ss << msg; \
    return ss.str(); \
  }())
#define STRg(msg...) \
  ([]() { \
    std::ostringstream ss; \
    ss << msg; \
    return ss.str(); \
  }())
#define CSTR(msg...) (STR(msg).c_str())


template<typename T>
inline std::ostream& operator<<(std::ostream &os, const std::vector<T> &v) {
  bool fst = true;
  for (auto &e : v) {
    if (fst)
      fst = false;
    else
      os << " ";
    os << e;
  }
  return os;
}

template<typename T>
inline std::vector<T> operator+(const std::vector<T> &v1, const std::vector<T> &v2) {
  std::vector<T> res = v1;
  res.insert(res.end(), v2.begin(), v2.end());
  return res;
}

class Run {
public:
  Run(const std::function<void()> &fnAction) { fnAction(); }
};

class OnDestroy {
  std::function<void()> fnAction;
public:
  OnDestroy(const std::function<void()> &newFnAction);
  ~OnDestroy();
  void doNow();
};

class RunAtEnd : public std::unique_ptr<OnDestroy> {
public:
  RunAtEnd();
  RunAtEnd(const std::function<void()> &newFnAction);
  void reset(const std::function<void()> &newFnAction);
  void doNow();
};

// RAII wrapper for file descriptors
class UniqueFd {
  int fd_;
public:
  explicit UniqueFd(int fd = -1) : fd_(fd) {}
  ~UniqueFd() { if (fd_ >= 0) ::close(fd_); }
  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;
  UniqueFd(UniqueFd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
  UniqueFd& operator=(UniqueFd&& o) noexcept {
    if (fd_ >= 0) ::close(fd_);
    fd_ = o.fd_; o.fd_ = -1;
    return *this;
  }
  int get() const { return fd_; }
  int release() { int f = fd_; fd_ = -1; return f; }
  void reset(int fd = -1) { if (fd_ >= 0) ::close(fd_); fd_ = fd; }
};

//
// utility functions
//

namespace Util {

// exec-based execution: no shell involved, immune to command injection
void execCommand(const std::vector<std::string> &argv, const std::string &what);
int execCommandGetStatus(const std::vector<std::string> &argv, const std::string &what); // returns raw wait status
std::string execCommandGetOutput(const std::vector<std::string> &argv, const std::string &what);
// exec-based pipeline: chain of commands connected by pipes
void execPipeline(const std::vector<std::vector<std::string>> &cmds, const std::string &what,
                  const std::string &stdinFile = "", const std::string &stdoutFile = "");
std::string execPipelineGetOutput(const std::vector<std::vector<std::string>> &cmds, const std::string &what,
                                  const std::string &stdinFile = "");
void ckSyscallError(int res, const char *syscall, const char *arg, const std::function<bool(int)> whiteWash = [](int err) {return false;});
std::string tmSecMs();
std::string filePathToBareName(const std::string &path);
std::string filePathToFileName(const std::string &path);
int getSysctlInt(const char *name);
void setSysctlInt(const char *name, int value);
std::string getSysctlString(const char *name);
void ensureKernelModuleIsLoaded(const char *name);
int getFreeBSDMajorVersion();
std::string gethostname();
std::vector<std::string> splitString(const std::string &str, const std::string &delimiter);
std::string stripTrailingSpace(const std::string &str);
unsigned toUInt(const std::string &str);
std::string pathSubstituteVarsInPath(const std::string &path);
std::string pathSubstituteVarsInString(const std::string &str);
std::vector<std::string> reverseVector(const std::vector<std::string> &v);
std::string shellQuote(const std::string &arg);
std::string safePath(const std::string &path, const std::string &requiredPrefix, const std::string &what);

namespace Fs {

bool fileExists(const std::string &path);
bool dirExists(const std::string &path);
std::vector<std::string> readFileLines(int fd);
size_t getFileSize(int fd);
void writeFile(const std::string &data, int fd);
void writeFile(const std::string &data, const std::string &file);
void appendFile(const std::string &data, const std::string &file);
void chmod(const std::string &path, mode_t mode);
void chown(const std::string &path, uid_t owner, gid_t group);
void link(const std::string &name1, const std::string &name2);
void unlink(const std::string &file);
void mkdir(const std::string &dir, mode_t mode);
void rmdir(const std::string &dir);
void rmdirFlat(const std::string &dir);
void rmdirHier(const std::string &dir);
bool rmdirFlatExcept(const std::string &dir, const std::set<std::string> &except);
bool rmdirHierExcept(const std::string &dir, const std::set<std::string> &except);
bool isXzArchive(const char *file);
char isElfFileOrDir(const std::string &file); // returns 'E'LF, 'D'ir, or 'N'o
std::set<std::string> findElfFiles(const std::string &dir);
bool hasExtension(const char *file, const char *extension);
void copyFile(const std::string &srcFile, const std::string &dstFile);
std::vector<std::string> expandWildcards(const std::string &wildcardPath, const std::string &rootPrefix = "");
bool isOnZfs(const std::string &path);
std::string getZfsDataset(const std::string &path);
bool isZfsEncrypted(const std::string &dataset);
bool isZfsKeyLoaded(const std::string &dataset);

}

}
