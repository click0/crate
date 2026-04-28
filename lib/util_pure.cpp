// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure (platform-independent) helpers from lib/util.cpp, extracted so
// they can be linked into unit tests on Linux without dragging in
// FreeBSD-specific dependencies (sysctl, sha256, fetch, capsicum, etc.).
//
// The remaining lib/util.cpp keeps everything that needs FreeBSD or
// rang.hpp.

#include "util.h"
#include "err.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <sstream>

#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <errno.h>
#include <string.h>

namespace Util {

static uid_t pure_myuid = ::getuid();

static const char sepFilePath = '/';
static const char sepFileExt  = '.';

std::string filePathToBareName(const std::string &path) {
  auto i = path.rfind(sepFilePath);
  std::string p = (i != std::string::npos ? path.substr(i + 1) : path);
  i = p.find(sepFileExt);
  return i != std::string::npos ? p.substr(0, i) : p;
}

std::string filePathToFileName(const std::string &path) {
  auto i = path.rfind(sepFilePath);
  return i != std::string::npos ? path.substr(i + 1) : path;
}

std::vector<std::string> splitString(const std::string &str, const std::string &delimiter) {
  std::vector<std::string> res;
  std::string s = str;

  size_t pos = 0;
  while ((pos = s.find(delimiter)) != std::string::npos) {
    if (pos > 0)
      res.push_back(s.substr(0, pos));
    s.erase(0, pos + delimiter.length());
  }
  if (!s.empty())
    res.push_back(s);

  return res;
}

std::string stripTrailingSpace(const std::string &str) {
  unsigned sz = str.size();
  while (sz > 0 && ::isspace(str[sz-1]))
    sz--;
  return str.substr(0, sz);
}

unsigned toUInt(const std::string &str) {
  // Reject leading '-' explicitly: std::stoul will silently wrap it
  // around to ULONG_MAX, which would otherwise pass through as a
  // huge "valid" unsigned. Whitespace is also rejected for
  // consistency with the previous behaviour (stoul skipped it,
  // which made " 80" parse as 80 — surprising for a port-number
  // parser).
  if (!str.empty() && (str.front() == '-' || std::isspace(str.front())))
    ERR2("convert string to unsigned", "invalid numeric string '" << str << "'")
  std::size_t pos = 0;
  unsigned long u = 0;
  try {
    u = std::stoul(str, &pos);
  } catch (const std::invalid_argument &) {
    ERR2("convert string to unsigned", "invalid numeric string '" << str << "'")
  } catch (const std::out_of_range &) {
    ERR2("convert string to unsigned", "number out of range '" << str << "'")
  }
  if (pos != str.size())
    ERR2("convert string to unsigned", "trailing characters in string '" << str << "'")
  // On 64-bit platforms unsigned long is 64-bit; reject values that
  // would silently truncate when cast to unsigned (32-bit).
  if (u > std::numeric_limits<unsigned>::max())
    ERR2("convert string to unsigned", "number out of range '" << str << "'")
  return static_cast<unsigned>(u);
}

std::vector<std::string> reverseVector(const std::vector<std::string> &v) {
  auto vc = v;
  std::reverse(vc.begin(), vc.end());
  return vc;
}

std::string shellQuote(const std::string &arg) {
  std::ostringstream ss;
  ss << '\'';
  for (auto chr : arg)
    if (chr == '\'')
      ss << "'\\''";
    else
      ss << chr;
  ss << '\'';
  return ss.str();
}

std::string safePath(const std::string &path, const std::string &requiredPrefix, const std::string &what) {
  namespace fs = std::filesystem;
  auto canonical = fs::weakly_canonical(path).string();
  // Require both: prefix match AND a path-separator immediately after.
  // Without the separator check, prefix "/foo" would wrongly accept the
  // unrelated path "/foobar/x".
  if (canonical.size() < requiredPrefix.size() ||
      canonical.compare(0, requiredPrefix.size(), requiredPrefix) != 0 ||
      (canonical.size() > requiredPrefix.size() &&
       canonical[requiredPrefix.size()] != '/'))
    ERR2("path validation", "'" << what << "' path '" << path << "' resolves to '"
         << canonical << "' which is outside required prefix '" << requiredPrefix << "'")
  return canonical;
}

bool isUrl(const std::string &str) {
  return str.size() > 8 && (str.substr(0, 7) == "http://" || str.substr(0, 8) == "https://");
}

std::string pathSubstituteVarsInPath(const std::string &path) {
  if (path.size() > 5 && path.substr(0, 5) == "$HOME") {
    auto *pw = ::getpwuid(pure_myuid);
    if (pw == nullptr)
      ERR2("path substitution", "getpwuid failed for uid " << pure_myuid << ": " << strerror(errno))
    return STR(pw->pw_dir << path.substr(5));
  }

  return path;
}

std::string pathSubstituteVarsInString(const std::string &str) {
  auto substOne = [](const std::string &s_in, const std::string &key, const std::string &val) {
    // Walk the string with an explicit cursor so that finding `key`
    // followed by an alphanumeric (e.g. "$HOME" inside "$HOMER")
    // advances past that match instead of looping forever.
    std::string s = s_in;
    size_t pos = 0;
    while (pos < s.size()) {
      auto off = s.find(key, pos);
      if (off == std::string::npos)
        break;
      bool wordBoundary = (off + key.size() == s.size() ||
                           !std::isalnum(s[off + key.size()]));
      if (wordBoundary) {
        s = STR(s.substr(0, off) << val << s.substr(off + key.size()));
        pos = off + val.size();
      } else {
        pos = off + key.size();
      }
    }
    return s;
  };

  auto *uidInfo = ::getpwuid(pure_myuid);
  if (uidInfo == nullptr)
    ERR2("string substitution", "getpwuid failed for uid " << pure_myuid << ": " << strerror(errno))
  std::string s = str;
  for (auto kv : std::map<std::string, std::string>({{"$HOME", uidInfo->pw_dir}, {"$USER", uidInfo->pw_name}}))
    s = substOne(s, kv.first, kv.second);

  return s;
}

namespace Fs {

bool hasExtension(const char *file, const char *extension) {
  auto ext = ::strrchr(file, '.');
  return ext != nullptr && ::strcmp(ext, extension) == 0;
}

bool fileExists(const std::string &path) {
  struct stat sb;
  return ::stat(path.c_str(), &sb) == 0 && sb.st_mode & S_IFREG;
}

bool dirExists(const std::string &path) {
  struct stat sb;
  return ::stat(path.c_str(), &sb) == 0 && sb.st_mode & S_IFDIR;
}

std::string getUserHomeDir() {
  struct passwd *pw = ::getpwuid(::getuid());
  if (pw && pw->pw_dir)
    return pw->pw_dir;
  return "";
}

}

}
