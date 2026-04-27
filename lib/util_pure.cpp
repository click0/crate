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
#include <sstream>

namespace Util {

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
  return u;
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

namespace Fs {

bool hasExtension(const char *file, const char *extension) {
  auto ext = ::strrchr(file, '.');
  return ext != nullptr && ::strcmp(ext, extension) == 0;
}

}

}
