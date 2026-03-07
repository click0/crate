// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// DRM session using libseat.

#include "drm_session.h"

#ifdef HAVE_LIBSEAT
#include <libseat.h>
#endif

#include <unistd.h>
#include <fcntl.h>

namespace DrmSession {

#ifdef HAVE_LIBSEAT
static struct libseat *g_seat = nullptr;
static int g_deviceId = -1;

static void seatEnableHandler(struct libseat *, void *) {}
static void seatDisableHandler(struct libseat *, void *) {
  if (g_seat)
    libseat_disable_seat(g_seat);
}

static struct libseat_seat_listener g_listener = {
  .enable_seat = seatEnableHandler,
  .disable_seat = seatDisableHandler,
};
#endif

bool available() {
#ifdef HAVE_LIBSEAT
  return true;
#else
  return false;
#endif
}

bool openSession() {
#ifdef HAVE_LIBSEAT
  if (g_seat) return true;
  g_seat = libseat_open_seat(&g_listener, nullptr);
  return g_seat != nullptr;
#else
  return false;
#endif
}

int openDevice(const std::string &path) {
#ifdef HAVE_LIBSEAT
  if (!g_seat) return -1;
  int fd = libseat_open_device(g_seat, path.c_str(), &g_deviceId);
  return fd;
#else
  // Fallback: direct open (requires appropriate permissions)
  return ::open(path.c_str(), O_RDWR);
#endif
}

void closeDevice(int fd) {
#ifdef HAVE_LIBSEAT
  if (g_seat && g_deviceId >= 0)
    libseat_close_device(g_seat, g_deviceId);
  g_deviceId = -1;
#endif
  if (fd >= 0)
    ::close(fd);
}

void closeSession() {
#ifdef HAVE_LIBSEAT
  if (g_seat) {
    libseat_close_seat(g_seat);
    g_seat = nullptr;
  }
#endif
}

}
