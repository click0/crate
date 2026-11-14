// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers from lib/run_gui.cpp:
//   - VESA CVT (Coordinated Video Timing) reduced-blanking modeline.
//   - Resolution resolution from spec.
//   - Xorg config generator for headless GPU mode.

#pragma once

#include <string>
#include <vector>

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

// 0.8.44: list of PipeWire socket files crate looks for under
// $XDG_RUNTIME_DIR when wiring `gui: auto`. Files that don't
// exist on a particular host are skipped silently — operators
// running PulseAudio (no PipeWire) or systems without audio see
// no error; the helper is best-effort.
//
// Order matters for two reasons:
//   1. pipewire-0 must be bound before pipewire-0-manager;
//      libpipewire opens them in this order.
//   2. The list defines what `crate doctor` should report as
//      "missing" vs "expected absent".
//
// Returned list is fixed and convention-based — PipeWire's socket
// names aren't operator-configurable in the spec. PulseAudio
// compat (pulse/native) is intentionally NOT in the list — it
// lives under a subdir of $XDG_RUNTIME_DIR which our flat bind
// strategy doesn't support yet; tracked for a follow-up.
std::vector<std::string> pipewireSocketNames();

// 0.8.47: PulseAudio compatibility socket subpath under
// $XDG_RUNTIME_DIR. Returned as a relative path with a slash
// because PulseAudio convention puts its socket inside a
// `pulse/` sub-directory:
//   $XDG_RUNTIME_DIR/pulse/native
// crate creates the in-jail `pulse/` sub-dir on demand and
// nullfs-binds the socket file. Apps still using PulseAudio
// rather than PipeWire native (Discord, OBS Studio's PulseAudio
// backend, some legacy Qt apps) need this; modern firefox /
// chromium prefer PipeWire and don't.
//
// Returned as a single string rather than a list because there's
// only one PulseAudio socket per session (unlike PipeWire which
// has core + manager). If a future need arises (pulse/cli for
// inspector tools), promote to a list.
std::string pulseSocketRelpath();

// 1.1.74: the jail's /tmp/.X11-unix in gui nested / headless / gpu mode.
// It was a nullfs of the host's whole /tmp/.X11-unix, so DISPLAY=:0 in
// the jail reached the host's own X server, and :N every other run's
// Xvfb (started -ac). Now crate makes a private directory inside the
// host's /tmp/.X11-unix (the same filesystem as the socket, so a hard
// link to it cannot fail with EXDEV), links only its own server's
// socket into it and mounts that directory. mkdtemp(3) template for it:
std::string ownXSocketDirTemplate();
// "X<N>", the socket an X server on display :N creates.
std::string xSocketName(unsigned displayNum);
// The host path is such a directory, or inside one (crate audit).
bool isOwnXSocketDir(const std::string &hostPath);
// 1.1.78: the same private-directory arrangement for the shared mode,
// holding the HOST display's socket (it mounted the host's whole
// /tmp/.X11-unix read-write). A name of its own, so that `crate audit`
// still tells "the host display" from "this run's own server":
// mkdtemp(3) fills the X's with letters and digits, never a '-', so an
// own-server directory cannot be taken for this one.
std::string hostXSocketDirTemplate();
bool isHostXSocketDir(const std::string &hostPath);

// 1.1.74: whether copyX11Auth gives the jail the host's .Xauthority /
// .ICEauthority. Only a jail that talks to the host's X server needs
// the host cookie, i.e. the shared mode. nested (Xephyr), headless
// (Xvfb) and gpu (Xorg) run their own server, which crate starts
// without access control; none, compositor and wayland bind no host X
// socket at all. Before 1.1.74 the cookie went to nested too (with the
// whole host /tmp/.X11-unix: a jail could connect to the host display
// with a valid cookie), and to compositor / none / wayland / auto
// resolved to headless or gpu.
//   guiMode       — the resolved mode (resolveGuiMode: shared, nested,
//                   headless, gpu, none, compositor)
//   waylandOnly   — `gui.mode: wayland`, which resolves to shared
//   x11Mode       — the x11 option's mode, "" without x11 options
//   clipboardMode — the clipboard option's mode, "" without it
// The pre-1.1.74 rules for the shared mode stay: no cookie with
// `x11.mode: none`, nor with `clipboard.mode: none` unless the x11 mode
// is nested.
bool hostX11CookieWanted(const std::string &guiMode, bool waylandOnly,
                         const std::string &x11Mode,
                         const std::string &clipboardMode);

// 1.1.78: the X servers crate starts (Xvfb, Xephyr, Xorg) ran without
// access control — Xvfb with `-ac`, the other two with no `-auth`, which
// to an X server means "every local client is welcome". Their sockets
// sit in the host's /tmp/.X11-unix, so any local user, and any jail the
// shared X11 mode gave that directory to, could read the keystrokes and
// the screen of another tenant's headless / nested / gpu display. Now
// each run makes a 16-byte MIT-MAGIC-COOKIE-1 and starts its server with
// `-auth <file>`; the same file goes into the jail (XAUTHORITY) and to
// the clients crate itself starts against that display (x11vnc, the
// embedded VNC server, `crate gui screenshot`).
//
// One record of an Xauthority(5) file: family, address, display number,
// protocol name, data — each a 2-byte big-endian length and the bytes
// (the family is a bare 2-byte number). The family is FamilyWild with an
// empty address: the record matches whatever host name the client has
// (the jail's differs from the host's), and the number ties it to this
// display. "" when the cookie is not kXCookieSize bytes.
constexpr unsigned kXCookieSize = 16;
std::string xauthorityEntry(unsigned displayNum, const std::string &cookie);

// 1.1.78: the display number of a DISPLAY that names a local X server
// through its Unix socket — ":0", ":0.0", "unix:1", "unix:1.0" — or -1
// (a TCP display such as "localhost:10.0" from ssh -X, a launchd path,
// garbage). The shared X11 mode mounts just /tmp/.X11-unix/X<N> for it.
int localDisplayNumber(const std::string &display);

// 1.1.78: websockify's two address arguments. It was started as
// `websockify <port> localhost:<vncPort>` — no listen address, so the
// noVNC stream was served on every interface while x11vnc itself was on
// loopback, and with a non-loopback gui/vnc_bind x11vnc was not on
// "localhost" at all. `bind` is the resolved gui/vnc_bind
// (CompositorPure::resolveVncBind): websockify listens there, and
// connects to x11vnc there (loopback when the bind is a wildcard). IPv6
// literals are bracketed, as websockify wants them.
std::string websockifyListenArg(const std::string &bind, unsigned wsPort);
std::string websockifyTargetArg(const std::string &bind, unsigned vncPort);

// 1.1.78: gui/wayland_security_context — what `gui: auto` and
// `gui.mode: wayland` put in the jail as the Wayland socket.
//   auto     (default) a socket the compositor restricts
//            (wp_security_context_v1, lib/wayland_security_context.h)
//            when it can make one; the host compositor's own socket,
//            with the 1.1.77 warning, when it cannot
//   require  the restricted socket or no run at all
//   off      the host compositor's own socket — for a jail that is
//            meant to have the privileged protocols (a panel, a screen
//            recorder, a whole desktop session inside the jail)
enum class WaylandContextMode { Auto, Require, Off };
// "" is Auto. false for anything but auto / require / off.
bool parseWaylandContextMode(const std::string &s, WaylandContextMode &out);
// What to bind once the compositor has been asked (contextMade: it gave
// a restricted socket). Off never asks.
enum class WaylandBind { Restricted, Raw, Refuse };
WaylandBind waylandBindDecision(WaylandContextMode mode, bool contextMade);
// mkdtemp(3) template of the private host directory holding the
// restricted socket, under the operator's XDG_RUNTIME_DIR; and whether a
// host path lies in such a directory (crate audit).
std::string waylandContextDirTemplate(const std::string &xdgRuntimeDir);
bool isWaylandContextDir(const std::string &hostPath);
// Spec validation, "" when fine. The key only means something where a
// host Wayland socket can be bound (gui/mode auto or wayland).
std::string waylandContextKeyError(const std::string &guiMode, const std::string &value);
// 1.1.78: gui/vnc_bind was refused outside gui/mode=compositor, although
// x11vnc (nested / headless / gpu) has taken it since 1.1.48 and
// websockify takes it now — so the X11 modes could not be reached from
// another machine except through websockify's accidental "every
// interface". "" when the mode can have a VNC server (all but wayland).
std::string vncBindKeyError(const std::string &guiMode);

// 1.1.77: which shared-mode security warnings setupX11 must emit. The
// shared path binds the host operator's own display socket into the
// jail: the X11 bind gives every keystroke and window on the host X
// server (no inter-client isolation), and the raw Wayland socket gives
// the compositor's privileged protocols (virtual keyboard/pointer,
// screencopy, data-control, foreign-toplevel) — either reaches the
// whole host session, other jails' windows included, so it is not a
// boundary between tenants. Each warning belongs to a socket that is
// bound: the X11 one not to a Wayland-only run (it routes through the
// shared block but binds no X11 socket); `wayland` says a Wayland
// socket may be bound — setupX11 prints that warning once the mount
// has happened (WAYLAND_DISPLAY can name a socket that is not there).
//   isAutoFlow     — `gui: auto` (or `gui.mode: auto`)
//   isWaylandFlow  — `gui.mode: wayland`
//   displaySet     — DISPLAY is set in the environment
//   waylandSet     — WAYLAND_DISPLAY is set and non-empty
//   xdgRuntimeSet  — XDG_RUNTIME_DIR is set (needed to locate the socket)
struct SharedDisplayWarnings {
  bool x11;
  bool wayland;
};
SharedDisplayWarnings sharedDisplayWarnings(bool isAutoFlow, bool isWaylandFlow,
                                            bool displaySet, bool waylandSet,
                                            bool xdgRuntimeSet);

}
