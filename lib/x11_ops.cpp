// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// X11 display management using libX11/libXrandr.

#include "x11_ops.h"

#ifdef HAVE_X11
#include <X11/Xlib.h>
#include <X11/extensions/Xrandr.h>
#endif

#include <string.h>

namespace X11Ops {

bool available() {
#ifdef HAVE_X11
  return true;
#else
  return false;
#endif
}

bool isDisplayAvailable(const std::string &display) {
#ifdef HAVE_X11
  Display *dpy = XOpenDisplay(display.c_str());
  if (!dpy) return false;
  XCloseDisplay(dpy);
  return true;
#else
  (void)display;
  return false;
#endif
}

bool getResolution(const std::string &display, unsigned &width, unsigned &height) {
#ifdef HAVE_X11
  Display *dpy = XOpenDisplay(display.c_str());
  if (!dpy) return false;

  int screen = DefaultScreen(dpy);
  width = DisplayWidth(dpy, screen);
  height = DisplayHeight(dpy, screen);
  XCloseDisplay(dpy);
  return true;
#else
  (void)display; (void)width; (void)height;
  return false;
#endif
}

bool setResolution(const std::string &display, unsigned width, unsigned height) {
#ifdef HAVE_X11
  Display *dpy = XOpenDisplay(display.c_str());
  if (!dpy) return false;

  int screen = DefaultScreen(dpy);
  Window root = RootWindow(dpy, screen);

  XRRScreenConfiguration *sc = XRRGetScreenInfo(dpy, root);
  if (!sc) {
    XCloseDisplay(dpy);
    return false;
  }

  // Find matching size
  int nsizes;
  XRRScreenSize *sizes = XRRConfigSizes(sc, &nsizes);
  Rotation rotation;
  XRRConfigCurrentConfiguration(sc, &rotation);

  for (int i = 0; i < nsizes; i++) {
    if (static_cast<unsigned>(sizes[i].width) == width &&
        static_cast<unsigned>(sizes[i].height) == height) {
      XRRSetScreenConfig(dpy, sc, root, i, rotation, CurrentTime);
      XRRFreeScreenConfigInfo(sc);
      XCloseDisplay(dpy);
      return true;
    }
  }

  // No exact match — try XRRSetScreenSize for virtual size
  XRRSetScreenSize(dpy, root, width, height,
                   static_cast<int>(width * 25.4 / 96),
                   static_cast<int>(height * 25.4 / 96));

  XRRFreeScreenConfigInfo(sc);
  XCloseDisplay(dpy);
  return true;
#else
  (void)display; (void)width; (void)height;
  return false;
#endif
}

bool screenshot(const std::string &display, const std::string &outputPath) {
#ifdef HAVE_X11
  Display *dpy = XOpenDisplay(display.c_str());
  if (!dpy) return false;

  int screen = DefaultScreen(dpy);
  Window root = RootWindow(dpy, screen);
  unsigned w = DisplayWidth(dpy, screen);
  unsigned h = DisplayHeight(dpy, screen);

  XImage *img = XGetImage(dpy, root, 0, 0, w, h, AllPlanes, ZPixmap);
  if (!img) {
    XCloseDisplay(dpy);
    return false;
  }

  // Write as PPM (simple format, can be converted later)
  FILE *fp = ::fopen(outputPath.c_str(), "wb");
  if (fp) {
    ::fprintf(fp, "P6\n%u %u\n255\n", w, h);
    for (unsigned y = 0; y < h; y++) {
      for (unsigned x = 0; x < w; x++) {
        unsigned long pixel = XGetPixel(img, x, y);
        unsigned char r = (pixel >> 16) & 0xff;
        unsigned char g = (pixel >> 8) & 0xff;
        unsigned char b = pixel & 0xff;
        ::fwrite(&r, 1, 1, fp);
        ::fwrite(&g, 1, 1, fp);
        ::fwrite(&b, 1, 1, fp);
      }
    }
    ::fclose(fp);
  }

  XDestroyImage(img);
  XCloseDisplay(dpy);
  return fp != nullptr;
#else
  (void)display; (void)outputPath;
  return false;
#endif
}

}
