// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "run_gui_pure.h"
#include "spec.h"

#include <cstddef>
#include <iomanip>
#include <sstream>
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

std::string generateGpuXorgConf(unsigned displayNum,
                                const std::string &resolution,
                                const std::string &gpuDriver,
                                const std::string &gpuDevice) {
  (void)displayNum;
  unsigned w = 0, h = 0;
  if (!parseResolution(resolution, w, h)) {
    w = 1280;
    h = 720;
  }
  auto cvt = computeCvtModeline(w, h);
  auto driver = gpuDriver.empty() ? std::string("dummy") : gpuDriver;

  std::ostringstream conf;
  conf << std::fixed << std::setprecision(2);

  conf << "Section \"Device\"\n";
  conf << "    Identifier \"GPU0\"\n";
  conf << "    Driver     \"" << driver << "\"\n";
  if (!gpuDevice.empty())
    conf << "    BusID      \"" << gpuDevice << "\"\n";
  if (driver == "nvidia") {
    conf << "    Option     \"AllowEmptyInitialConfiguration\" \"True\"\n";
    conf << "    Option     \"ConnectedMonitor\" \"DFP-0\"\n";
    conf << "    Option     \"CustomEDID\" \"DFP-0:/usr/local/share/crate/edid/1080p.bin\"\n";
  }
  conf << "EndSection\n\n";

  conf << "Section \"Monitor\"\n";
  conf << "    Identifier \"Monitor0\"\n";
  conf << "    HorizSync   28.0-200.0\n";
  conf << "    VertRefresh  48.0-75.0\n";
  conf << "    Modeline \"" << resolution << "\" "
       << cvt.pixelClock
       << " " << cvt.hdisp << " " << cvt.hsyncStart << " " << cvt.hsyncEnd << " " << cvt.htotal
       << " " << cvt.vdisp << " " << cvt.vsyncStart << " " << cvt.vsyncEnd << " " << cvt.vtotal
       << " +hsync -vsync\n";
  conf << "EndSection\n\n";

  conf << "Section \"Screen\"\n";
  conf << "    Identifier \"Screen0\"\n";
  conf << "    Device     \"GPU0\"\n";
  conf << "    Monitor    \"Monitor0\"\n";
  conf << "    DefaultDepth 24\n";
  conf << "    SubSection \"Display\"\n";
  conf << "        Depth      24\n";
  conf << "        Modes      \"" << resolution << "\"\n";
  conf << "        Virtual    " << w << " " << h << "\n";
  conf << "    EndSubSection\n";
  conf << "EndSection\n\n";

  conf << "Section \"ServerLayout\"\n";
  conf << "    Identifier \"Layout0\"\n";
  conf << "    Screen 0   \"Screen0\"\n";
  conf << "    Option     \"AllowMouseOpenFail\" \"true\"\n";
  conf << "    Option     \"AutoAddDevices\" \"false\"\n";
  conf << "    Option     \"AutoAddGPU\" \"false\"\n";
  conf << "EndSection\n\n";

  conf << "Section \"ServerFlags\"\n";
  conf << "    Option \"DontVTSwitch\" \"true\"\n";
  conf << "    Option \"AllowMouseOpenFail\" \"true\"\n";
  conf << "    Option \"PciForceNone\" \"true\"\n";
  conf << "    Option \"AutoEnableDevices\" \"false\"\n";
  conf << "    Option \"AutoAddDevices\" \"false\"\n";
  conf << "EndSection\n";

  return conf.str();
}

std::string resolveAutoMode(bool displaySet, bool waylandSet, bool hasGpu) {
  // Either compositor reachable from the host -> shared path. The
  // setupX11 shared block already binds /tmp/.X11-unix; the new
  // 0.8.18 logic also copies $XAUTHORITY and (if waylandSet) binds
  // the Wayland socket.
  if (displaySet || waylandSet) return "shared";
  if (hasGpu) return "gpu";
  return "headless";
}

std::vector<std::string> pipewireSocketNames() {
  // pipewire-0:           main client API socket
  // pipewire-0-manager:   admin/discovery socket (some clients
  //                       open both; mute/level changes use it)
  // PulseAudio compat (pulse/native) is intentionally omitted —
  // see header comment.
  return { "pipewire-0", "pipewire-0-manager" };
}

std::string pulseSocketRelpath() {
  // Single string — there's only one PulseAudio socket per
  // session ($XDG_RUNTIME_DIR/pulse/native). The runtime
  // creates the `pulse/` sub-dir in the jail before binding.
  return "pulse/native";
}

std::string ownXSocketDirTemplate() {
  return "/tmp/.X11-unix/.crate-XXXXXXXX";
}

std::string xSocketName(unsigned displayNum) {
  return "X" + std::to_string(displayNum);
}

bool isOwnXSocketDir(const std::string &hostPath) {
  static const std::string prefix = "/tmp/.X11-unix/.crate-";
  return hostPath.size() > prefix.size() && hostPath.compare(0, prefix.size(), prefix) == 0
         && !isHostXSocketDir(hostPath);
}

std::string hostXSocketDirTemplate() {
  return "/tmp/.X11-unix/.crate-host-XXXXXXXX";
}

bool isHostXSocketDir(const std::string &hostPath) {
  static const std::string prefix = "/tmp/.X11-unix/.crate-host-";
  return hostPath.size() > prefix.size() && hostPath.compare(0, prefix.size(), prefix) == 0;
}

bool hostX11CookieWanted(const std::string &guiMode, bool waylandOnly,
                         const std::string &x11Mode,
                         const std::string &clipboardMode) {
  if (guiMode != "shared" || waylandOnly) return false;
  if (x11Mode == "none") return false;
  if (clipboardMode == "none" && !x11Mode.empty() && x11Mode != "nested") return false;
  return true;
}

std::string parseWaylandDisplay(const std::string &waylandDisplayEnv) {
  if (waylandDisplayEnv.empty()) return "";
  // Reject anything that looks like a path — only basename form
  // (the wayland-cli convention) is supported.
  if (waylandDisplayEnv.find('/') != std::string::npos) return "";
  // Reject path traversal sentinels.
  if (waylandDisplayEnv == "." || waylandDisplayEnv == "..") return "";
  // Reject absurdly long inputs (Unix socket paths are bounded
  // anyway by sockaddr_un.sun_path which is ~108 bytes).
  if (waylandDisplayEnv.size() > 64) return "";
  // Reject control chars / shell metas; allow [A-Za-z0-9._-] which
  // covers wayland-0, wayland-1, etc.
  for (char c : waylandDisplayEnv) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') continue;
    return "";
  }
  return waylandDisplayEnv;
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

std::string xauthorityEntry(unsigned displayNum, const std::string &cookie) {
  if (cookie.size() != kXCookieSize) return "";
  static const std::string name = "MIT-MAGIC-COOKIE-1";
  const std::string number = std::to_string(displayNum);
  std::string out;
  auto put16 = [&out](size_t v) {
    out.push_back((char)((v >> 8) & 0xff));
    out.push_back((char)(v & 0xff));
  };
  auto putField = [&](const std::string &f) { put16(f.size()); out += f; };
  put16(0xffff);          // FamilyWild
  putField("");           // address
  putField(number);
  putField(name);
  putField(cookie);
  return out;
}

int localDisplayNumber(const std::string &display) {
  std::string d = display;
  if (d.compare(0, 5, "unix:") == 0) d = d.substr(4);
  if (d.size() < 2 || d[0] != ':') return -1;
  size_t i = 1;
  int n = 0;
  while (i < d.size() && d[i] >= '0' && d[i] <= '9') {
    if (i > 5) return -1;   // X<N> beyond 99999 is no display
    n = n * 10 + (d[i] - '0');
    i++;
  }
  if (i == 1) return -1;
  if (i == d.size()) return n;
  // ".<screen>"
  if (d[i] != '.' || i + 1 == d.size()) return -1;
  for (size_t j = i + 1; j < d.size(); j++)
    if (d[j] < '0' || d[j] > '9') return -1;
  return n;
}

static std::string bracketed(const std::string &host) {
  return host.find(':') != std::string::npos ? "[" + host + "]" : host;
}

std::string websockifyListenArg(const std::string &bind, unsigned wsPort) {
  return bracketed(bind) + ":" + std::to_string(wsPort);
}

std::string websockifyTargetArg(const std::string &bind, unsigned vncPort) {
  std::string host = bind;
  if (host == "0.0.0.0") host = "127.0.0.1";
  else if (host == "::") host = "::1";
  return bracketed(host) + ":" + std::to_string(vncPort);
}

bool parseWaylandContextMode(const std::string &s, WaylandContextMode &out) {
  if (s.empty() || s == "auto") { out = WaylandContextMode::Auto; return true; }
  if (s == "require") { out = WaylandContextMode::Require; return true; }
  if (s == "off") { out = WaylandContextMode::Off; return true; }
  return false;
}

WaylandBind waylandBindDecision(WaylandContextMode mode, bool contextMade) {
  if (mode == WaylandContextMode::Off) return WaylandBind::Raw;
  if (contextMade) return WaylandBind::Restricted;
  return mode == WaylandContextMode::Require ? WaylandBind::Refuse : WaylandBind::Raw;
}

std::string waylandContextDirTemplate(const std::string &xdgRuntimeDir) {
  return xdgRuntimeDir + "/crate-wl-XXXXXXXX";
}

bool isWaylandContextDir(const std::string &hostPath) {
  static const std::string mark = "/crate-wl-";
  const auto p = hostPath.find(mark);
  // "<dir>/crate-wl-<8 chars>" itself or something inside it
  return p != std::string::npos && hostPath.size() >= p + mark.size() + 8;
}

std::string waylandContextKeyError(const std::string &guiMode, const std::string &value) {
  WaylandContextMode m;
  if (!parseWaylandContextMode(value, m))
    return "gui/wayland_security_context must be 'auto', 'require' or 'off'";
  if (guiMode != "auto" && guiMode != "wayland")
    return "gui/wayland_security_context is only valid with gui/mode auto or wayland";
  return "";
}

std::string vncBindKeyError(const std::string &guiMode) {
  if (guiMode == "wayland")
    return "gui/vnc_bind is not valid with gui/mode=wayland (no VNC server is started)";
  return "";
}

SharedDisplayWarnings sharedDisplayWarnings(bool isAutoFlow, bool isWaylandFlow,
                                            bool displaySet, bool waylandSet,
                                            bool xdgRuntimeSet) {
  SharedDisplayWarnings w;
  // X11 socket is bound for shared/auto when DISPLAY is set; a
  // Wayland-only run skips the X11 bind, so it must not warn about X11.
  w.x11 = !isWaylandFlow && displaySet;
  // The host Wayland socket is bound for auto (on a Wayland host) and
  // for explicit wayland, needing both WAYLAND_DISPLAY and the runtime
  // dir to locate it.
  w.wayland = (isAutoFlow || isWaylandFlow) && waylandSet && xdgRuntimeSet;
  return w;
}

}
