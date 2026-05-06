// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "net_detect.h"
#include "net_detect_pure.h"
#include "util.h"

#include <mutex>

namespace NetDetect {

namespace {

std::mutex   g_mu;
bool         g_cacheValid = false;
std::string  g_cachedIface;

} // anon

std::string defaultIfaceCached() {
  std::lock_guard<std::mutex> lock(g_mu);
  if (g_cacheValid) return g_cachedIface;

  std::string out;
  try {
    out = Util::execCommandGetOutput(
      {"/sbin/route", "-4", "get", "default"},
      "route -4 get default");
  } catch (...) {
    // route(8) missing / no default route. Return empty; caller
    // treats it as "not detected" and falls back to operator
    // configuration or skips auto-fw.
    g_cachedIface = "";
    g_cacheValid  = true;
    return "";
  }

  g_cachedIface = NetDetectPure::parseRouteOutput(out);
  g_cacheValid  = true;
  return g_cachedIface;
}

void clearCache() {
  std::lock_guard<std::mutex> lock(g_mu);
  g_cacheValid = false;
  g_cachedIface.clear();
}

} // namespace NetDetect
