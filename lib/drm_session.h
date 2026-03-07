// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// DRM/GPU session management using libseat.
// For gui: mode: gpu — correct DRM device acquisition without suid.
// Compile with WITH_LIBSEAT and link -lseat.

#pragma once

#include <string>

namespace DrmSession {

bool available();

// Open a seat session. Must be called before openDevice.
bool openSession();

// Open a DRM device by path (e.g. "/dev/dri/card0").
// Returns file descriptor, or -1 on failure.
int openDevice(const std::string &path);

// Release a DRM device.
void closeDevice(int fd);

// Close the seat session.
void closeSession();

}
