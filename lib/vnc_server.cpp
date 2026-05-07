// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Embedded VNC server using libvncserver.
// 0.8.22 enhancement: when both HAVE_X11 and HAVE_LIBVNCSERVER are
// defined at build time, the server polls the host's X11 root window
// of the given display via XGetImage and copies the frame into the
// libvncserver framebuffer at ~25 FPS. This makes the embedded
// server a real alternative to fork+exec'ing x11vnc.

#include "vnc_server.h"
#include "err.h"

#ifdef HAVE_LIBVNCSERVER
#include <rfb/rfb.h>
#endif

#ifdef HAVE_X11
#include <X11/Xlib.h>
#endif

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>

#define ERR(msg...) ERR2("vnc", msg)

namespace VncServer {

#ifdef HAVE_LIBVNCSERVER
static rfbScreenInfoPtr g_screen = nullptr;
static std::thread       g_thread;
static std::atomic<bool> g_running{false};
static unsigned          g_port = 0;
static int               g_width = 0;
static int               g_height = 0;
#ifdef HAVE_X11
static Display          *g_display = nullptr;
static Window            g_root    = 0;
#endif
#endif

bool available() {
#ifdef HAVE_LIBVNCSERVER
  return true;
#else
  return false;
#endif
}

#if defined(HAVE_LIBVNCSERVER) && defined(HAVE_X11)
// Poll X11 root every 40ms (25 FPS), copy XImage into the
// libvncserver framebuffer, mark the whole region modified.
// libvncserver handles dirty-rect compression on its side.
static void grabLoop(unsigned displayNum) {
  char dispName[16];
  std::snprintf(dispName, sizeof(dispName), ":%u", displayNum);
  g_display = XOpenDisplay(dispName);
  if (g_display == nullptr) {
    g_running = false;
    return;
  }
  g_root = DefaultRootWindow(g_display);

  while (g_running) {
    XImage *img = XGetImage(g_display, g_root, 0, 0,
                            (unsigned)g_width, (unsigned)g_height,
                            AllPlanes, ZPixmap);
    if (img != nullptr) {
      // libvncserver framebuffer is BGRA; XImage is typically the
      // same on FreeBSD's default visual. Skip per-pixel byteswap
      // for the common case; if visual is exotic the operator
      // sees a colour-swapped frame and can fall back to x11vnc.
      if ((int)g_screen->paddedWidthInBytes == img->bytes_per_line) {
        std::memcpy(g_screen->frameBuffer, img->data,
                    (size_t)img->bytes_per_line * (size_t)img->height);
      } else {
        // Row-by-row when pad differs.
        for (int y = 0; y < img->height && y < g_height; y++) {
          std::memcpy(g_screen->frameBuffer + (size_t)y * g_screen->paddedWidthInBytes,
                      img->data + (size_t)y * img->bytes_per_line,
                      (size_t)std::min(img->bytes_per_line, (int)g_screen->paddedWidthInBytes));
        }
      }
      rfbMarkRectAsModified(g_screen, 0, 0, g_width, g_height);
      XDestroyImage(img);
    }
    rfbProcessEvents(g_screen, 40000); // 40ms = 25fps
  }

  if (g_display != nullptr) {
    XCloseDisplay(g_display);
    g_display = nullptr;
  }
}
#endif

unsigned start(unsigned displayNum, unsigned port, const std::string &password) {
#ifdef HAVE_LIBVNCSERVER
  if (g_running) return g_port;

  // Probe the actual display resolution before constructing the
  // VNC framebuffer so we don't serve a stretched / clipped frame.
  // Without HAVE_X11 we can't probe; fall back to 1024x768 and
  // the framebuffer stays blank.
  int width = 1024, height = 768;
#ifdef HAVE_X11
  {
    char dispName[16];
    std::snprintf(dispName, sizeof(dispName), ":%u", displayNum);
    Display *probe = XOpenDisplay(dispName);
    if (probe != nullptr) {
      Window root = DefaultRootWindow(probe);
      Window dummyRoot;
      int dx, dy;
      unsigned int dw, dh, dbw, ddepth;
      if (XGetGeometry(probe, root, &dummyRoot, &dx, &dy, &dw, &dh, &dbw, &ddepth)) {
        width  = (int)dw;
        height = (int)dh;
      }
      XCloseDisplay(probe);
    }
  }
#endif
  g_width  = width;
  g_height = height;

  int argc = 0;
  g_screen = rfbGetScreen(&argc, nullptr, width, height, 8, 3, 4);
  if (!g_screen) return 0;

  g_screen->frameBuffer = static_cast<char*>(::malloc((size_t)width * (size_t)height * 4));
  if (!g_screen->frameBuffer) {
    rfbScreenCleanup(g_screen);
    g_screen = nullptr;
    return 0;
  }
  ::memset(g_screen->frameBuffer, 0, (size_t)width * (size_t)height * 4);

  g_screen->port = (port > 0) ? port : 5900 + displayNum;
  g_screen->alwaysShared = TRUE;

  if (!password.empty()) {
    static char *passwords[2] = {nullptr, nullptr};
    if (passwords[0]) ::free(passwords[0]);
    passwords[0] = ::strdup(password.c_str());
    g_screen->authPasswdData = passwords;
    g_screen->passwordCheck = rfbCheckPasswordByList;
  }

  rfbInitServer(g_screen);
  g_port = g_screen->port;

  g_running = true;
#ifdef HAVE_X11
  g_thread = std::thread([displayNum]() { grabLoop(displayNum); });
#else
  // No X11 support compiled in — server runs but framebuffer
  // never gets updated. Operator-visible warning at the call
  // site; we just spin rfbProcessEvents to keep the protocol live.
  (void)displayNum;
  g_thread = std::thread([]() {
    while (g_running && g_screen)
      rfbProcessEvents(g_screen, 40000);
  });
#endif

  return g_port;
#else
  (void)displayNum; (void)port; (void)password;
  return 0;
#endif
}

void stop() {
#ifdef HAVE_LIBVNCSERVER
  g_running = false;
  if (g_thread.joinable())
    g_thread.join();
  if (g_screen) {
    if (g_screen->frameBuffer)
      ::free(g_screen->frameBuffer);
    rfbScreenCleanup(g_screen);
    g_screen = nullptr;
  }
  g_port = 0;
  g_width = g_height = 0;
#endif
}

bool isRunning() {
#ifdef HAVE_LIBVNCSERVER
  return g_running;
#else
  return false;
#endif
}

unsigned getPort() {
#ifdef HAVE_LIBVNCSERVER
  return g_port;
#else
  return 0;
#endif
}

}
