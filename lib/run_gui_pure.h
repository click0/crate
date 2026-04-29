// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers from lib/run_gui.cpp:
//   - VESA CVT (Coordinated Video Timing) reduced-blanking modeline.
//   - Resolution resolution from spec.
//   - Xorg config generator for headless GPU mode.

#pragma once

#include <string>

class Spec;

namespace RunGuiPure {

struct CvtModeline {
  double   pixelClock;   // MHz
  unsigned hdisp, hsyncStart, hsyncEnd, htotal;
  unsigned vdisp, vsyncStart, vsyncEnd, vtotal;
};

// Compute CVT-RB modeline for arbitrary resolution (VESA CVT v1.1).
CvtModeline computeCvtModeline(unsigned w, unsigned h, double refresh = 60.0);

// Pick effective resolution from spec.guiOptions / spec.x11Options
// (in that order), falling back to "1280x720".
std::string resolveResolution(const Spec &spec);

// Parse "WxH" → (w, h). Returns false on malformed input.
bool parseResolution(const std::string &spec, unsigned &w, unsigned &h);

}
