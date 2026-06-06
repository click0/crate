// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers for `gui.mode: compositor` — running a Wayland
// compositor (sway, weston, cage, labwc, …) *inside* a jail, as
// opposed to `gui.mode: wayland` which binds the host compositor's
// socket for in-jail Wayland *clients*.
//
// Two backends (operator picks via `gui.backend`):
//   - headless: WLR_BACKEND=headless, offscreen render, exposed over
//     VNC (wayvnc). No /dev/input, no DRM master — safe, composes
//     with the host display.
//   - drm:      WLR_BACKEND=drm, the jail drives the physical GPU +
//       input directly. Needs /dev/dri/* + /dev/input/* unhidden and
//       a seatd session. Powerful but a real privilege surface — the
//       jail effectively "owns the screen".
//
// Everything here is side-effect free so it can be unit-tested
// without a jail, a GPU, or seatd. The side-effectful wiring
// (mounts, jexec, fork) lives in lib/run_gui.cpp / lib/run.cpp.

#pragma once

#include <string>
#include <utility>
#include <vector>

namespace CompositorPure {

enum class Backend { Headless, Drm };

// Parse the `gui.backend` spec value.
//   "" / "headless" -> Headless   (headless is the safe default)
//   "drm"           -> Drm
// Returns false on any other value (caller turns this into a spec error).
bool parseBackend(const std::string &s, Backend &out);

// Canonical lowercase name ("headless" / "drm").
const char *backendName(Backend b);

// Split a `gui.compositor` command string into an argv vector.
//
// We exec the result via jexec WITHOUT an intervening shell, so the
// string is a plain command + arguments, whitespace-separated. Shell
// features (pipes, redirects, command substitution, globbing, &&)
// are NOT supported and are rejected rather than silently passed
// through as literal argv — an operator who needs them should point
// `gui.compositor` at a wrapper script.
//
// Returns false (and sets err) when the command is empty/blank or any
// token contains a shell metacharacter or a NUL.
bool parseCompositorCommand(const std::string &cmd,
                            std::vector<std::string> &argv,
                            std::string &err);

// devfs(8) `unhide` path globs the jail's /dev needs for this backend.
//   Headless, gpuAccel=false -> {}                       (pure software)
//   Headless, gpuAccel=true  -> {"dri","dri/*"}          (render node for EGL/Vulkan)
//   Drm                      -> {"dri","dri/*","input/*"}(KMS + input devices)
// Patterns are devfs rule path globs (no leading slash), matching the
// shape lib/run.cpp already uses for the GPU auto-unhide.
std::vector<std::string> requiredDevfsUnhide(Backend b, bool gpuAccel);

// Does this backend need a seatd session to open DRM master + input?
// Headless -> false; Drm -> true.
bool needsSeatd(Backend b);

// Candidate seatd socket paths to look for on the host (and bind into
// the jail), most-conventional first.
std::vector<std::string> seatdSocketCandidates();

// The Wayland socket name a freshly-started compositor will create in
// an isolated, empty XDG_RUNTIME_DIR (wl_display_add_socket_auto
// begins at wayland-0). Used to point wayvnc / in-jail clients at the
// right socket.
const char *defaultWaylandSocket();

// Compose the environment for the in-jail compositor process.
//   runtimeDir : XDG_RUNTIME_DIR inside the jail (e.g. "/tmp/wayland").
//   seatdSock  : in-jail path of the bound seatd socket, or "" if none
//                (only consulted for the Drm backend).
//   gpuAccel   : a render node is available -> gles2 renderer, else
//                the pixman software renderer (headless only; drm is
//                always GPU-backed).
// Returned as ordered (key,value) pairs (stable for testing).
std::vector<std::pair<std::string, std::string>>
composeEnv(Backend b, const std::string &runtimeDir,
           const std::string &seatdSock, bool gpuAccel);

// Build the wayvnc argument vector (excluding the binary path) for
// exposing a headless compositor's output over VNC:
//   wayvnc <host> <port>
std::vector<std::string> wayvncArgs(const std::string &host, unsigned port);

// Resolve the address wayvnc should bind to inside the jail.
//   requested == "" -> "127.0.0.1" (secure default: loopback only — the
//                      VNC stream is unauthenticated, so don't expose it
//                      on every jail address by default).
//   otherwise       -> the requested value, after validation.
// Validation: the value is passed to wayvnc as a bare argv token (exec,
// no shell), so it must look like an address/hostname — [A-Za-z0-9.:_-],
// non-empty, <=255 chars. Anything else (whitespace, shell metachars,
// control bytes) is rejected with `err` set, and `out` is left empty.
bool resolveVncBind(const std::string &requested, std::string &out, std::string &err);

// True when a resolved bind address exposes VNC beyond the loopback
// (i.e. is NOT 127.0.0.1 / ::1 / localhost). Callers warn on this when
// no authentication is configured.
bool vncBindIsPublic(const std::string &bind);

} // namespace CompositorPure
