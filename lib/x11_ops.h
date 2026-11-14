// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// X11 display management using libX11/libXrandr.
// Compile with WITH_X11 and link -lX11 -lXrandr -lXext.

#pragma once

#include <string>

namespace X11Ops {

bool available();

// 1.1.78: the MIT-MAGIC-COOKIE-1 (raw bytes) the following calls in this
// process present to the server — for the displays crate starts with
// `-auth`. Xlib keeps it process-wide (XSetAuthorization); the
// environment, which child processes inherit for the HOST display, is
// left alone. A no-op without libX11.
void useCookie(const std::string &cookie);

// Check if an X display is accessible.
bool isDisplayAvailable(const std::string &display);

// Get the current resolution of a display.
bool getResolution(const std::string &display, unsigned &width, unsigned &height);

// Set the resolution using XRandR.
bool setResolution(const std::string &display, unsigned width, unsigned height);

// Take a screenshot of the root window, save as PNM.
bool screenshot(const std::string &display, const std::string &outputPath);

}
