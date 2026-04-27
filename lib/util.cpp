// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "util.h"
#include "zfs_ops.h"
#include "pathnames.h"
#include "err.h"

#include <string>
#include <vector>
#include <set>
#include <map>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <functional>
#include <filesystem>
#include <algorithm>
#include <cctype>

#include <rang.hpp>

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sha256.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/linker.h>
#include <sys/wait.h>
#include <pwd.h>
#include <fnmatch.h>


#define SYSCALL(res, syscall, arg ...) Util::ckSyscallError(res, syscall, arg)

static uid_t myuid = ::getuid();

// consts (sepFilePath/sepFileExt moved to lib/util_pure.cpp)

// OnDestroy/RunAtEnd

OnDestroy::OnDestroy(const std::function<void()> &newFnAction) : fnAction(newFnAction) { }

OnDestroy::~OnDestroy() {
  // releasing the resource in destructor, likely cumulative after some exception, catch the potential exception here
  try {
    fnAction();
  } catch (const Exception &e) {
    std::cerr << rang::fg::yellow << "EXCEPTION while another error is in progress: " << e.what() << rang::style::reset << std::endl;
  } catch (const std::exception& e) {
    std::cerr << "EXCEPTION while another error is in progress (std::exception):" << rang::fg::red << e.what() << rang::style::reset << std::endl;
  } catch (...) {
    std::cerr << rang::fg::red << "UNKNOWN EXCEPTION while another error is in progress: " << rang::style::reset << std::endl;
  }
}

void OnDestroy::doNow() {
  fnAction(); // releasing the resource in a regular way: let exceptions propagate
  fnAction = []() { };
}

RunAtEnd::RunAtEnd()
{ }

RunAtEnd::RunAtEnd(const std::function<void()> &newFnAction)
: std::unique_ptr<OnDestroy>(new OnDestroy(newFnAction))
{ }

void RunAtEnd::reset(const std::function<void()> &newFnAction) {
  std::unique_ptr<OnDestroy>::reset(new OnDestroy(newFnAction));
}

void RunAtEnd::doNow() {
  get()->doNow();
}


namespace Util {

// Convert vector<string> argv to char*[] for execv
static std::vector<char*> toExecArgv(const std::vector<std::string> &argv) {
  std::vector<char*> cargv;
  cargv.reserve(argv.size() + 1);
  for (auto &a : argv)
    cargv.push_back(const_cast<char*>(a.c_str()));
  cargv.push_back(nullptr);
  return cargv;
}

void execCommand(const std::vector<std::string> &argv, const std::string &what) {
  if (argv.empty())
    ERR2("exec command", "empty argv for: " << what)
  auto cargv = toExecArgv(argv);
  pid_t pid = ::fork();
  if (pid == -1)
    ERR2("exec command", "fork failed for '" << what << "': " << strerror(errno))
  if (pid == 0) {
    // child
    ::execv(cargv[0], cargv.data());
    ::_exit(127); // exec failed
  }
  // parent: wait for child
  int status;
  while (::waitpid(pid, &status, 0) == -1) {
    if (errno != EINTR)
      ERR2("exec command", "waitpid failed for '" << what << "': " << strerror(errno))
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    ERR2("exec command", "'" << what << "' failed with exit status " << code)
  }
}

int execCommandGetStatus(const std::vector<std::string> &argv, const std::string &what) {
  if (argv.empty())
    ERR2("exec command", "empty argv for: " << what)
  auto cargv = toExecArgv(argv);
  pid_t pid = ::fork();
  if (pid == -1)
    ERR2("exec command", "fork failed for '" << what << "': " << strerror(errno))
  if (pid == 0) {
    // child
    ::execv(cargv[0], cargv.data());
    ::_exit(127); // exec failed
  }
  // parent: wait for child, return raw wait status
  int status;
  while (::waitpid(pid, &status, 0) == -1) {
    if (errno != EINTR)
      ERR2("exec command", "waitpid failed for '" << what << "': " << strerror(errno))
  }
  return status;
}

std::string execCommandGetOutput(const std::vector<std::string> &argv, const std::string &what) {
  if (argv.empty())
    ERR2("exec command", "empty argv for: " << what)
  int pipefd[2];
  if (::pipe(pipefd) == -1)
    ERR2("exec command", "pipe failed for '" << what << "': " << strerror(errno))
  UniqueFd pipeRead(pipefd[0]), pipeWrite(pipefd[1]);
  auto cargv = toExecArgv(argv);
  pid_t pid = ::fork();
  if (pid == -1)
    ERR2("exec command", "fork failed for '" << what << "': " << strerror(errno))
  if (pid == 0) {
    // child: redirect stdout to pipe write end (no RAII in child — exec replaces process)
    ::close(pipeRead.release());
    ::dup2(pipeWrite.get(), STDOUT_FILENO);
    ::close(pipeWrite.release());
    ::execv(cargv[0], cargv.data());
    ::_exit(127);
  }
  // parent: read from pipe read end
  pipeWrite.reset(); // close write end
  std::ostringstream ss;
  char buf[4096];
  ssize_t nbytes;
  while ((nbytes = ::read(pipeRead.get(), buf, sizeof(buf))) > 0)
    ss.write(buf, nbytes);
  pipeRead.reset(); // close read end
  // wait for child
  int status;
  while (::waitpid(pid, &status, 0) == -1) {
    if (errno != EINTR)
      ERR2("exec command", "waitpid failed for '" << what << "': " << strerror(errno))
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    ERR2("exec command", "'" << what << "' failed with exit status " << code)
  }
  return ss.str();
}

// Internal: run a pipeline of commands, optionally capturing last stdout into a string
static std::string execPipelineImpl(const std::vector<std::vector<std::string>> &cmds, const std::string &what,
                                    const std::string &stdinFile, const std::string &stdoutFile, bool capture) {
  if (cmds.empty())
    ERR2("exec pipeline", "empty pipeline for: " << what)

  int n = cmds.size();
  // Create n-1 pipes
  std::vector<int> pipefds(2 * (n - 1));
  for (int i = 0; i < n - 1; i++) {
    if (::pipe(&pipefds[2*i]) == -1) {
      // Close already-created pipes on failure
      for (int j = 0; j < 2*i; j++) ::close(pipefds[j]);
      ERR2("exec pipeline", "pipe() failed for '" << what << "': " << strerror(errno))
    }
  }

  // Capture pipe for last process stdout (when capture=true)
  int capturePipe[2] = {-1, -1};
  if (capture) {
    if (::pipe(capturePipe) == -1) {
      for (auto fd : pipefds) ::close(fd);
      ERR2("exec pipeline", "pipe() failed for capture: " << strerror(errno))
    }
  }

  // Scope guard: close all pipe fds if an exception occurs during fork
  bool pipesClosedByParent = false;
  RunAtEnd pipeGuard([&]() {
    if (!pipesClosedByParent) {
      for (auto fd : pipefds) if (fd >= 0) ::close(fd);
      if (capturePipe[0] >= 0) ::close(capturePipe[0]);
      if (capturePipe[1] >= 0) ::close(capturePipe[1]);
    }
  });

  // Fork children
  std::vector<pid_t> pids(n);
  for (int i = 0; i < n; i++) {
    auto cargv = toExecArgv(cmds[i]);
    pid_t pid = ::fork();
    if (pid == -1)
      ERR2("exec pipeline", "fork() failed for '" << what << "': " << strerror(errno))
    if (pid == 0) {
      // child i
      // stdin: from previous pipe or stdinFile (for first)
      if (i == 0 && !stdinFile.empty()) {
        int fd = ::open(stdinFile.c_str(), O_RDONLY);
        if (fd == -1) ::_exit(127);
        ::dup2(fd, STDIN_FILENO);
        ::close(fd);
      } else if (i > 0) {
        ::dup2(pipefds[2*(i-1)], STDIN_FILENO);
      }
      // stdout: to next pipe, or stdoutFile/capture (for last)
      if (i < n - 1) {
        ::dup2(pipefds[2*i+1], STDOUT_FILENO);
      } else {
        if (!stdoutFile.empty()) {
          int fd = ::open(stdoutFile.c_str(), O_WRONLY|O_CREAT|O_TRUNC, 0644);
          if (fd == -1) ::_exit(127);
          ::dup2(fd, STDOUT_FILENO);
          ::close(fd);
        } else if (capture) {
          ::dup2(capturePipe[1], STDOUT_FILENO);
        }
      }
      // close all pipe fds in child
      for (auto fd : pipefds) ::close(fd);
      if (capturePipe[0] >= 0) ::close(capturePipe[0]);
      if (capturePipe[1] >= 0) ::close(capturePipe[1]);
      ::execv(cargv[0], cargv.data());
      ::_exit(127);
    }
    pids[i] = pid;
  }

  // Parent: close all pipe fds (scope guard no longer needed)
  pipesClosedByParent = true;
  for (auto fd : pipefds) ::close(fd);
  if (capturePipe[1] >= 0) ::close(capturePipe[1]);

  // Read captured output if needed
  std::ostringstream ss;
  if (capture) {
    char buf[4096];
    ssize_t nbytes;
    while ((nbytes = ::read(capturePipe[0], buf, sizeof(buf))) > 0)
      ss.write(buf, nbytes);
    ::close(capturePipe[0]);
  }

  // Wait for all children
  bool failed = false;
  for (int i = 0; i < n; i++) {
    int status;
    while (::waitpid(pids[i], &status, 0) == -1) {
      if (errno != EINTR)
        ERR2("exec pipeline", "waitpid failed for '" << what << "': " << strerror(errno))
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
      failed = true;
  }
  if (failed)
    ERR2("exec pipeline", "'" << what << "' pipeline failed")

  return ss.str();
}

void execPipeline(const std::vector<std::vector<std::string>> &cmds, const std::string &what,
                  const std::string &stdinFile, const std::string &stdoutFile) {
  execPipelineImpl(cmds, what, stdinFile, stdoutFile, false);
}

std::string execPipelineGetOutput(const std::vector<std::vector<std::string>> &cmds, const std::string &what,
                                  const std::string &stdinFile) {
  return execPipelineImpl(cmds, what, stdinFile, "", true);
}

void ckSyscallError(int res, const char *syscall, const char *arg, const std::function<bool(int)> whiteWash) {
  if (res == -1 && !whiteWash(errno))
    ERR2("system call", "'" << syscall << "' failed, arg=" << arg << ": " << strerror(errno))
}

std::string tmSecMs() {
  static bool firstTime = true;
  static timeval tpStart;
  if (firstTime) {
    gettimeofday(&tpStart, NULL);
    firstTime = false;
  }

  struct timeval tp;
  gettimeofday(&tp, NULL);

  auto sec = tp.tv_sec - tpStart.tv_sec;
  auto usec = tp.tv_usec - tpStart.tv_usec;
  if (usec < 0) {
    sec--;
    usec += 1000000;
  }

  return STR(sec << "." << std::setw(3) << std::setfill('0') << usec/1000);
}

// filePathToBareName, filePathToFileName moved to lib/util_pure.cpp

int getSysctlInt(const char *name) {
  int value;
  size_t size = sizeof(value);

  SYSCALL(::sysctlbyname(name, &value, &size, nullptr, 0), "sysctlbyname (get int)", name);

  return value;
}

void setSysctlInt(const char *name, int value) {
  SYSCALL(::sysctlbyname(name, nullptr, nullptr, &value, sizeof(value)), "sysctlbyname (set int)", name);
}

std::string getSysctlString(const char *name) {
  char buf[256];
  size_t size = sizeof(buf) - 1;
  SYSCALL(::sysctlbyname(name, buf, &size, nullptr, 0), "sysctlbyname (get string)", name);
  buf[size] = 0;
  return buf;
}

void ensureKernelModuleIsLoaded(const char *name) {
  SYSCALL(::kldload(name), "kldload", name, [](int err) {return err == EEXIST;});
}

int getFreeBSDMajorVersion() {
  auto osrelease = getSysctlString("kern.osrelease");
  try { return std::stoi(osrelease); } catch (...) { return 0; }
}

std::string gethostname() {
  char name[256];
  SYSCALL(::gethostname(name, sizeof(name)), "gethostname", "");
  return name;
}

// splitString, stripTrailingSpace, toUInt moved to lib/util_pure.cpp

std::string pathSubstituteVarsInPath(const std::string &path) {
  if (path.size() > 5 && path.substr(0, 5) == "$HOME") {
    auto *pw = ::getpwuid(myuid);
    if (pw == nullptr)
      ERR2("path substitution", "getpwuid failed for uid " << myuid << ": " << strerror(errno))
    return STR(pw->pw_dir << path.substr(5));
  }

  return path;
}

std::string pathSubstituteVarsInString(const std::string &str) {
  auto substOne = [](const std::string &str, const std::string &key, const std::string &val) {
    std::string s = str;
    while (true) {
      auto off = s.find(key);
      if (off != std::string::npos && (off + key.size() == s.size() || !std::isalnum(s[off + key.size()])))
        s = STR(s.substr(0, off) << val << s.substr(off + key.size()));
      if (off == std::string::npos)
        break;
    }
    return s;
  };

  auto *uidInfo = ::getpwuid(myuid);
  if (uidInfo == nullptr)
    ERR2("string substitution", "getpwuid failed for uid " << myuid << ": " << strerror(errno))
  std::string s = str;
  for (auto kv : std::map<std::string, std::string>({{"$HOME", uidInfo->pw_dir}, {"$USER", uidInfo->pw_name}}))
    s = substOne(s, kv.first, kv.second);

  return s;
}

// reverseVector, shellQuote, safePath moved to lib/util_pure.cpp

std::string randomHex(int bytes) {
  std::vector<unsigned char> buf(bytes);
  ::arc4random_buf(buf.data(), buf.size());
  std::ostringstream ss;
  ss << std::hex << std::setfill('0');
  for (auto b : buf)
    ss << std::setw(2) << static_cast<int>(b);
  return ss.str();
}

std::string sha256hex(const std::string &input) {
  char hex[SHA256_DIGEST_STRING_LENGTH];
  SHA256_Data(reinterpret_cast<const uint8_t*>(input.data()), input.size(), hex);
  return std::string(hex);
}

// isUrl moved to lib/util_pure.cpp

std::string fetchUrl(const std::string &url, const std::string &destDir) {
  // Extract filename from URL
  auto slash = url.rfind('/');
  std::string fname = (slash != std::string::npos && slash + 1 < url.size())
    ? url.substr(slash + 1) : "downloaded-spec.yml";
  // Strip query string
  auto q = fname.find('?');
  if (q != std::string::npos) fname = fname.substr(0, q);
  if (fname.empty()) fname = "downloaded-spec.yml";

  auto destPath = destDir + "/" + fname;
  execCommand({CRATE_PATH_FETCH, "-q", "-o", destPath, url}, "fetch URL");
  return destPath;
}

bool interfaceExists(const std::string &ifaceName) {
  struct ifaddrs *ifap;
  if (::getifaddrs(&ifap) == -1)
    return false;
  bool found = false;
  for (struct ifaddrs *a = ifap; a; a = a->ifa_next) {
    if (ifaceName == a->ifa_name) {
      found = true;
      break;
    }
  }
  ::freeifaddrs(ifap);
  return found;
}

namespace Fs {

namespace fs = std::filesystem;

// fileExists, dirExists moved to lib/util_pure.cpp

std::vector<std::string> readFileLines(int fd) {
  std::vector<std::string> lines;

  // dup() the fd because fdopen()/fclose() takes ownership and closes it,
  // but the caller (e.g. FwUsers) still needs the original fd afterwards
  int dupfd = ::dup(fd);
  if (dupfd == -1)
    ERR2("read file", "dup failed: " << strerror(errno))
  // seek to start so we read from the beginning
  if (::lseek(dupfd, 0, SEEK_SET) == -1) {
    ::close(dupfd);
    ERR2("read file", "lseek failed: " << strerror(errno))
  }
  FILE *file = ::fdopen(dupfd, "r");
  if (file == nullptr) {
    ::close(dupfd);
    ERR2("read file", "fdopen failed: " << strerror(errno))
  }
  char *line = nullptr;
  size_t len = 0;
  ssize_t nread;
  // read lines
  while ((nread = ::getline(&line, &len, file)) != -1)
    lines.push_back(line);
  // error?
  if (::ferror(file)) {
    ::free(line);
    ::fclose(file);
    ERR2("read file", "reading file failed")
  }
  // clean up
  ::free(line);
  ::fclose(file); // closes dupfd, original fd is unaffected

  return lines;
}

size_t getFileSize(int fd) {
  struct stat sb;
  if (::fstat(fd, &sb) == -1)
    ERR2("get file size", STR("failed to stat the file: " << strerror(errno)))
  return sb.st_size;
}

void writeFile(const std::string &data, int fd) {
  auto res = ::write(fd, data.c_str(), data.size());
  if (res == -1) {
    auto err = STR("failed to write file: " << strerror(errno));
    (void)::close(fd);
    ERR2("write file", err)
  } else if (res != (int)data.size()) {
    (void)::close(fd);
    ERR2("write file", "short write in file, attempted to write " << data.size() << " bytes, actually wrote only " << res << " bytes")
  }
}

void writeFile(const std::string &data, const std::string &file) {
  int fd;
  SYSCALL(fd = ::open(file.c_str(), O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0644), "open", file.c_str());

  writeFile(data, fd);

  SYSCALL(::close(fd), "close", file.c_str());
}

void appendFile(const std::string &data, const std::string &file) {
  int fd;
  SYSCALL(fd = ::open(file.c_str(), O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW, 0644), "open", file.c_str());

  writeFile(data, fd);

  SYSCALL(::close(fd), "close", file.c_str());
}

void chmod(const std::string &path, mode_t mode) {
  SYSCALL(::chmod(path.c_str(), mode), "chmod", path.c_str());
}

void chown(const std::string &path, uid_t owner, gid_t group) {
  SYSCALL(::chown(path.c_str(), owner, group), "chown", path.c_str());
}

void link(const std::string &name1, const std::string &name2) {
  SYSCALL(::link(name1.c_str(), name2.c_str()), "link", name1.c_str());
}

void unlink(const std::string &file) {
  auto res = ::unlink(file.c_str());
  if (res == -1 && errno == EPERM) { // this unlink function clears the schg extended flag in case of EPERM, because in our context EPERM often indicates schg
    SYSCALL(::chflags(file.c_str(), 0/*flags*/), "chflags", file.c_str());
    SYSCALL(::unlink(file.c_str()), "unlink (2)", file.c_str()); // repeat the unlink call
    return;
  }
  SYSCALL(res, "unlink (1)", file.c_str());
}

void mkdir(const std::string &dir, mode_t mode) {
  SYSCALL(::mkdir(dir.c_str(), mode), "mkdir", dir.c_str());
}

void rmdir(const std::string &dir) {
  auto res = ::rmdir(dir.c_str());
  if (res == -1 && errno == EPERM) { // this rmdir function clears the schg extended flag in case of EPERM, because in our context EPERM often indicates schg
    SYSCALL(::chflags(dir.c_str(), 0/*flags*/), "chflags", dir.c_str());
    SYSCALL(::rmdir(dir.c_str()), "rmdir (2)", dir.c_str()); // repeat the rmdir call
    return;
  }
  SYSCALL(res, "rmdir (1)", dir.c_str());
}

void rmdirFlat(const std::string &dir) {
  for (const auto &entry : fs::directory_iterator(dir))
    unlink(entry.path());
  rmdir(dir);
}

void rmdirHier(const std::string &dir) {
  for (const auto &entry : fs::directory_iterator(dir)) {
    if (entry.is_symlink())
      unlink(entry.path());
    else if (entry.is_directory())
      rmdirHier(entry.path());
    else
      unlink(entry.path());
  }
  rmdir(dir);
}

bool rmdirFlatExcept(const std::string &dir, const std::set<std::string> &except) {
  bool someSkipped = false;
  for (const auto &entry : fs::directory_iterator(dir))
    if (except.find(entry.path()) == except.end())
      unlink(entry.path());
    else
      someSkipped = true;
  if (!someSkipped)
    rmdir(dir);
  return someSkipped;
}

bool rmdirHierExcept(const std::string &dir, const std::set<std::string> &except) {
  unsigned cntSkip = 0;
  for (const auto &entry : fs::directory_iterator(dir))
    if (except.find(entry.path()) == except.end()) {
      if (entry.is_symlink())
        unlink(entry.path());
      else if (entry.is_directory())
        cntSkip += rmdirHierExcept(entry.path(), except);
      else
        unlink(entry.path());
    } else {
      cntSkip++;
    }
  if (cntSkip == 0)
    rmdir(dir);
  return cntSkip > 0;
}

bool isXzArchive(const char *file) {
  int res;
  struct stat sb;
  res = ::stat(file, &sb);
  if (res == -1)
    return false; // can't stat: can't be an XZ archive file

  if (sb.st_mode & S_IFREG && sb.st_size > 0x100) { // the XZ archive file can't be too small
    uint8_t signature[5];
    // read the signature
    int fd = ::open(file, O_RDONLY);
    if (fd == -1)
      return false; // can't open: can't be an XZ archive
    auto res = ::read(fd, signature, sizeof(signature));
    if (res != sizeof(signature)) {
      (void)::close(fd);
      return false; // can't read the file or read returned not 5: can't be an XZ archive file
    }
    if (::close(fd) == -1)
      return false; // failed to close the file: there is something wrong, we don't accept it as an XZ archive
    // check signature
    return signature[0]==0xfd && signature[1]==0x37 && signature[2]==0x7a && signature[3]==0x58 && signature[4]==0x5a;
  } else {
    return false; // not a regular file: can't be an XZ archive file
  }
}

char isElfFileOrDir(const std::string &file) { // find if the file is a regular file, has the exec bit set, and is a dynamic ELF file
  int res;

  struct stat sb;
  res = ::stat(file.c_str(), &sb);
  if (res == -1) {
    WARN("isElfFile: failed to stat the file '" << file << "': " << strerror(errno))
    return 'N'; // ? what else to do after the above
  }

  // directory?
  if (sb.st_mode & S_IFDIR)
    return 'D';

  // object files aren't dynamic ELFs
  if (file.size() > 2 && file[file.size()-1] == 'o' && file[file.size()-2] == '.')
    return 'N';

  if (sb.st_mode & S_IFREG /*&& sb.st_mode & S_IXUSR*/ && sb.st_size > 0x80) { // this reference claims that ELF can be as small as 142 bytes: http://timelessname.com/elfbin/
    // x-bit is disabled above: some .so files have no exec bit, particularly /usr/lib/pam_*.so
    uint8_t signature[4];
    // read the signature
    int fd = ::open(file.c_str(), O_RDONLY);
    if (fd == -1) {
      WARN("isElfFile: failed to open the file '" << file << "': " << strerror(errno))
      return 'N'; // ? what else to do after the above
    }
    auto res = ::read(fd, signature, sizeof(signature));
    if (res == -1)
      WARN("isElfFile: failed to read signature from '" << file << "': " << strerror(errno))
    if (::close(fd) == -1)
      WARN("isElfFile: failed to close the file '" << file << "': " << strerror(errno))
    // decide
    return res == 4 && signature[0]==0x7f && signature[1]==0x45 && signature[2]==0x4c && signature[3]==0x46 ? 'E' : 'N';
  } else {
    return 'N';
  }
}

std::set<std::string> findElfFiles(const std::string &dir) {
  std::set<std::string> s;
  std::function<void(const std::string&)> addElfFilesToSet;
  addElfFilesToSet = [&s,&addElfFilesToSet](const std::string &dir) {
    for (const auto &entry : fs::directory_iterator(dir))
      switch (isElfFileOrDir(entry.path())) {
      case 'E':
        s.insert(entry.path());
        break;
      case 'D':
        addElfFilesToSet(entry.path());
        break;
      default:
        ; // do nothing
      }
  };

  addElfFilesToSet(dir);

  return s;
}

// hasExtension moved to lib/util_pure.cpp

void copyFile(const std::string &srcFile, const std::string &dstFile) {
  try {
    fs::copy_file(srcFile, dstFile);
  } catch (fs::filesystem_error& e) {
    ERR2("copy file", "could not copy '" << srcFile << "' to '" << dstFile << "': " << e.what())
  }
}

std::vector<std::string> expandWildcards(const std::string &wildcardPath, const std::string &rootPrefix) {
  // Filesystem-based wildcard expansion using fnmatch (no shell involved)
  auto lastSlash = wildcardPath.rfind('/');
  if (lastSlash == std::string::npos)
    return {};
  auto dir = wildcardPath.substr(0, lastSlash);
  auto pattern = wildcardPath.substr(lastSlash + 1);
  auto fullDir = rootPrefix + dir;
  std::vector<std::string> results;
  if (fs::exists(fullDir) && fs::is_directory(fullDir))
    for (const auto &entry : fs::directory_iterator(fullDir))
      if (::fnmatch(pattern.c_str(), entry.path().filename().c_str(), 0) == 0)
        results.push_back(dir + "/" + entry.path().filename().string());
  return results;
}

bool isOnZfs(const std::string &path) {
  struct statfs sfs;
  if (::statfs(path.c_str(), &sfs) == -1)
    return false;
  return std::string(sfs.f_fstypename) == "zfs";
}

std::string getZfsDataset(const std::string &path) {
  struct statfs sfs;
  if (::statfs(path.c_str(), &sfs) == -1)
    return "";
  if (std::string(sfs.f_fstypename) != "zfs")
    return "";
  return sfs.f_mntfromname;
}

bool isZfsEncrypted(const std::string &dataset) {
  return ZfsOps::isEncrypted(dataset);
}

bool isZfsKeyLoaded(const std::string &dataset) {
  return ZfsOps::isKeyLoaded(dataset);
}

// getUserHomeDir moved to lib/util_pure.cpp

}

}
