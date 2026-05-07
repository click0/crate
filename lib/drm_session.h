// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// DRM/GPU session management using libseat.
//
// 0.8.23: previously orphaned; now called by `crate doctor` to
// surface seatd setup issues before they bite at jail start time.
// The session+device APIs below are the foundation for the future
// rootless-containers TODO item, where crate sheds setuid root
// and needs libseat coordination to legitimately open
// /dev/dri/cardN from a regular user's session.
//
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

// 0.8.23: open + immediately release a device — used by doctor to
// verify seatd is reachable and the running user has the seat
// privilege the device requires. Returns true on success.
// Internally calls openSession + openDevice + closeDevice +
// closeSession so it's safe to call repeatedly without leaking
// session state.
bool probeDevice(const std::string &path);

}
