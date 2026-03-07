// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Embedded VNC server using libvncserver.

#include "vnc_server.h"
#include "err.h"

#ifdef HAVE_LIBVNCSERVER
#include <rfb/rfb.h>
#endif

#include <thread>
#include <atomic>

#define ERR(msg...) ERR2("vnc", msg)

namespace VncServer {

#ifdef HAVE_LIBVNCSERVER
static rfbScreenInfoPtr g_screen = nullptr;
static std::thread g_thread;
static std::atomic<bool> g_running{false};
static unsigned g_port = 0;
#endif

bool available() {
#ifdef HAVE_LIBVNCSERVER
  return true;
#else
  return false;
#endif
}

unsigned start(unsigned displayNum, unsigned port, const std::string &password) {
#ifdef HAVE_LIBVNCSERVER
  if (g_running) return g_port;

  int width = 1024, height = 768;
  int argc = 0;
  g_screen = rfbGetScreen(&argc, nullptr, width, height, 8, 3, 4);
  if (!g_screen) return 0;

  g_screen->frameBuffer = static_cast<char*>(::malloc(width * height * 4));
  if (!g_screen->frameBuffer) {
    rfbScreenCleanup(g_screen);
    g_screen = nullptr;
    return 0;
  }
  ::memset(g_screen->frameBuffer, 0, width * height * 4);

  g_screen->port = (port > 0) ? port : 5900 + displayNum;
  g_screen->alwaysShared = TRUE;

  if (!password.empty()) {
    // Note: libvncserver password handling is basic
    static char *passwords[2] = {nullptr, nullptr};
    passwords[0] = ::strdup(password.c_str());
    g_screen->authPasswdData = passwords;
    g_screen->passwordCheck = rfbCheckPasswordByList;
  }

  rfbInitServer(g_screen);
  g_port = g_screen->port;

  g_running = true;
  g_thread = std::thread([]() {
    while (g_running && g_screen)
      rfbProcessEvents(g_screen, 40000); // 40ms = 25fps
  });

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
