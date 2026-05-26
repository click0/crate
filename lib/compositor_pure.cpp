// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "compositor_pure.h"

namespace CompositorPure {

bool parseBackend(const std::string &s, Backend &out) {
  if (s.empty() || s == "headless") { out = Backend::Headless; return true; }
  if (s == "drm")                   { out = Backend::Drm;      return true; }
  return false;
}

const char *backendName(Backend b) {
  switch (b) {
    case Backend::Headless: return "headless";
    case Backend::Drm:      return "drm";
  }
  return "headless";
}

bool parseCompositorCommand(const std::string &cmd,
                            std::vector<std::string> &argv,
                            std::string &err) {
  argv.clear();
  err.clear();

  // Reject shell metacharacters outright. We exec without a shell, so
  // these would otherwise become literal argv tokens — surprising and
  // a foot-gun. A wrapper script is the supported escape hatch.
  // (Space and tab never reach this set — they're consumed as token
  // separators below; \n\r\v\f are hard-rejected as embedded controls.)
  static const std::string kForbidden = ";&|<>`$(){}[]*?!\\\"'\n\r\v\f";

  std::string token;
  auto flush = [&]() {
    if (!token.empty()) {
      argv.push_back(token);
      token.clear();
    }
  };

  for (char c : cmd) {
    if (c == '\0') { err = "command contains a NUL byte"; argv.clear(); return false; }
    if (c == ' ' || c == '\t') { flush(); continue; }
    if (kForbidden.find(c) != std::string::npos) {
      err = std::string("command contains unsupported shell metacharacter '") + c +
            "' — gui.compositor takes a plain command + args (no shell features); "
            "use a wrapper script for pipes/redirects/substitution";
      argv.clear();
      return false;
    }
    token += c;
  }
  flush();

  if (argv.empty()) {
    err = "gui.compositor is empty — give a command to run, e.g. 'sway' or 'cage firefox'";
    return false;
  }
  return true;
}

std::vector<std::string> requiredDevfsUnhide(Backend b, bool gpuAccel) {
  switch (b) {
    case Backend::Headless:
      if (gpuAccel) return {"dri", "dri/*"};
      return {};
    case Backend::Drm:
      return {"dri", "dri/*", "input/*"};
  }
  return {};
}

bool needsSeatd(Backend b) {
  return b == Backend::Drm;
}

std::vector<std::string> seatdSocketCandidates() {
  // FreeBSD's sysutils/seatd defaults to /var/run/seatd.sock; some
  // setups (and the Linux convention seatd also honors) use /run.
  return {"/var/run/seatd.sock", "/run/seatd.sock"};
}

const char *defaultWaylandSocket() {
  return "wayland-0";
}

std::vector<std::pair<std::string, std::string>>
composeEnv(Backend b, const std::string &runtimeDir,
           const std::string &seatdSock, bool gpuAccel) {
  std::vector<std::pair<std::string, std::string>> env;
  env.emplace_back("XDG_RUNTIME_DIR", runtimeDir);

  switch (b) {
    case Backend::Headless:
      env.emplace_back("WLR_BACKEND", "headless");
      env.emplace_back("WLR_HEADLESS_OUTPUTS", "1");
      // No physical input devices in headless mode — keep wlroots from
      // probing libinput (and from needing /dev/input).
      env.emplace_back("WLR_LIBINPUT_NO_DEVICES", "1");
      env.emplace_back("WLR_RENDERER", gpuAccel ? "gles2" : "pixman");
      break;
    case Backend::Drm:
      env.emplace_back("WLR_BACKEND", "drm");
      // DRM always has a GPU; gles2 is the sane default renderer.
      env.emplace_back("WLR_RENDERER", "gles2");
      if (!seatdSock.empty()) {
        env.emplace_back("LIBSEAT_BACKEND", "seatd");
        env.emplace_back("SEATD_SOCK", seatdSock);
      }
      break;
  }
  return env;
}

std::vector<std::string> wayvncArgs(const std::string &host, unsigned port) {
  return {host, std::to_string(port)};
}

} // namespace CompositorPure
