// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Embedded VNC server using libvncserver.
// 0.8.22: when both WITH_X11 and WITH_LIBVNCSERVER are present at
// build time, start() polls the X11 root window of the given
// display via XGetImage and copies the frame into the libvncserver
// framebuffer at ~25 FPS. With only WITH_LIBVNCSERVER the server
// still runs but serves a blank framebuffer (operator-visible
// warning logged at start). Wired in via spec.guiOptions->vncNative
// (`gui.vnc_native: true`).

#pragma once

#include <string>
#include <functional>

namespace VncServer {

bool available();

// Start an embedded VNC server polling X11 display `:displayNum`.
// Returns the VNC port, or 0 on failure. Server runs in a
// background thread; call stop() to terminate.
//
// 0.8.22: when libX11 is linked, the server discovers the
// display's actual resolution at start time via XGetGeometry —
// no need to pre-supply width/height.
unsigned start(unsigned displayNum, unsigned port = 0,
               const std::string &password = "");

// Stop the embedded VNC server.
void stop();

// Whether the server is currently running.
bool isRunning();

// Get the port the server is listening on.
unsigned getPort();

}
