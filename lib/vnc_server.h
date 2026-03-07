// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Embedded VNC server using libvncserver. Replaces fork+exec of x11vnc.
// Compile with WITH_LIBVNCSERVER and link -lvncserver.

#pragma once

#include <string>
#include <functional>

namespace VncServer {

bool available();

// Start an embedded VNC server on the given X11 display.
// Returns the VNC port, or 0 on failure.
// The server runs in a background thread; call stop() to terminate.
unsigned start(unsigned displayNum, unsigned port = 0,
               const std::string &password = "");

// Stop the embedded VNC server.
void stop();

// Whether the server is currently running.
bool isRunning();

// Get the port the server is listening on.
unsigned getPort();

}
