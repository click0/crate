// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "log_pure.h"

#include <string>

namespace LogPure {

std::string sanitizeName(const std::string &name) {
  std::string out;
  out.reserve(name.size());
  for (char c : name) {
    if (c == '/' || c == '\0' || c == '\\')
      out.push_back('_');
    else
      out.push_back(c);
  }
  // Collapse leading dots so we can't accidentally produce a hidden file
  // (".") or a parent reference ("..").
  size_t i = 0;
  while (i < out.size() && out[i] == '.') {
    out[i] = '_';
    i++;
  }
  if (out.empty())
    out = "unnamed";
  return out;
}

std::string createLogPath(const std::string &logsDir,
                          const std::string &kind,
                          const std::string &name) {
  return logsDir + "/" + kind + "-" + sanitizeName(name) + ".log";
}

}
