// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "run_gui_pure.h"
#include "spec.h"

#include <cstddef>
#include <string>

namespace RunGuiPure {

CvtModeline computeCvtModeline(unsigned w, unsigned h, double refresh) {
  CvtModeline m{};
  m.hdisp = w;
  m.vdisp = h;

  // CVT reduced blanking (RB) for flat panels / virtual displays
  constexpr double minVPorch = 3.0;
  constexpr unsigned rbHBlank = 160;
  constexpr unsigned rbVFrontPorch = 3;
  constexpr unsigned rbVSync = 4;
  constexpr double rbMinVBlank = 460.0;

  double hPeriodEst = ((1000000.0 / refresh) - rbMinVBlank) / (h + minVPorch);
  unsigned vbiLines = static_cast<unsigned>(rbMinVBlank / hPeriodEst) + 1;
  unsigned rbMinVbi = static_cast<unsigned>(rbVFrontPorch + rbVSync + minVPorch);
  if (vbiLines < rbMinVbi)
    vbiLines = rbMinVbi;

  m.vtotal = h + vbiLines;
  m.htotal = w + rbHBlank;
  m.pixelClock = (m.htotal * m.vtotal * refresh) / 1000000.0;

  m.hsyncStart = w + 48;
  m.hsyncEnd = m.hsyncStart + 32;

  m.vsyncStart = h + rbVFrontPorch;
  m.vsyncEnd = m.vsyncStart + rbVSync;

  return m;
}

std::string resolveResolution(const Spec &spec) {
  if (spec.guiOptions && !spec.guiOptions->resolution.empty())
    return spec.guiOptions->resolution;
  if (spec.x11Options && !spec.x11Options->resolution.empty())
    return spec.x11Options->resolution;
  return "1280x720";
}

bool parseResolution(const std::string &spec, unsigned &w, unsigned &h) {
  // Reject leading whitespace explicitly — std::stoul would otherwise
  // silently skip it, accepting " 1920x1080" as valid.
  if (spec.empty() || std::isspace(static_cast<unsigned char>(spec.front())))
    return false;
  auto x = spec.find('x');
  if (x == std::string::npos || x == 0 || x == spec.size() - 1)
    return false;
  // Also reject whitespace right after the 'x'.
  if (std::isspace(static_cast<unsigned char>(spec[x + 1])))
    return false;
  try {
    std::size_t p1 = 0, p2 = 0;
    auto ww = std::stoul(spec.substr(0, x), &p1);
    auto hh = std::stoul(spec.substr(x + 1), &p2);
    if (p1 != x || p2 != spec.size() - x - 1)
      return false;
    if (ww == 0 || hh == 0)
      return false;
    w = static_cast<unsigned>(ww);
    h = static_cast<unsigned>(hh);
    return true;
  } catch (...) {
    return false;
  }
}

}
