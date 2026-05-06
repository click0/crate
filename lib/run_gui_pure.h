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

// Generate the xorg.conf body for headless GPU mode.
// Resolution is "WxH" (e.g. "1920x1080"); driver "" → "dummy".
std::string generateGpuXorgConf(unsigned displayNum,
                                const std::string &resolution,
                                const std::string &gpuDriver,
                                const std::string &gpuDevice);

// 0.8.18: `gui: auto` resolution.
// Inputs:
//   displaySet  — host has $DISPLAY (X11 server reachable)
//   waylandSet  — host has $WAYLAND_DISPLAY (compositor reachable)
//   hasGpu      — host has /dev/dri/card0 OR /dev/nvidia0
// Returns one of:
//   "shared"    — shared X11 + cookie (and Wayland mount if also set)
//   "gpu"       — start Xorg in jail with the host's GPU
//   "headless"  — Xvfb / dummy
// The shared path takes priority when DISPLAY or WAYLAND_DISPLAY is
// set — that's what desktop-app jails want. Operators who want
// Xephyr (nested) write `gui: nested` explicitly.
std::string resolveAutoMode(bool displaySet,
                            bool waylandSet,
                            bool hasGpu);

// Parse the host's $WAYLAND_DISPLAY into the basename of the Unix
// socket that lives under $XDG_RUNTIME_DIR. Returns "" if the input
// is not a usable socket name.
//   ""              -> ""
//   "wayland-0"     -> "wayland-0"
//   "wayland-1"     -> "wayland-1"
//   "/abs/path/sok" -> "" (we only support the basename form;
//                          absolute-path Wayland sockets are rare
//                          and need a different mount strategy)
//   "../etc/passwd" -> "" (path traversal rejected)
std::string parseWaylandDisplay(const std::string &waylandDisplayEnv);

}
