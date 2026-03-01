// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "gui_registry.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define ERR(msg...) \
  ERR2("gui", msg)

// --- gui list ---

static void guiListJson(const std::vector<Ctx::GuiEntry> &entries) {
  std::cout << "[" << std::endl;
  for (size_t i = 0; i < entries.size(); i++) {
    auto &e = entries[i];
    std::cout << "  {";
    std::cout << "\"display\":" << e.displayNum;
    std::cout << ",\"pid\":" << e.ownerPid;
    std::cout << ",\"xpid\":" << e.xServerPid;
    std::cout << ",\"vnc_port\":" << e.vncPort;
    std::cout << ",\"mode\":\"" << e.mode << "\"";
    std::cout << ",\"jail\":\"" << e.jailName << "\"";
    std::cout << "}";
    if (i + 1 < entries.size()) std::cout << ",";
    std::cout << std::endl;
  }
  std::cout << "]" << std::endl;
}

static void guiListTable(const std::vector<Ctx::GuiEntry> &entries) {
  if (entries.empty()) {
    std::cout << "No active GUI sessions." << std::endl;
    return;
  }

  // Calculate column widths
  size_t wDisp = 7, wPid = 3, wXpid = 4, wVnc = 3, wMode = 4, wJail = 4;
  for (auto &e : entries) {
    wDisp = std::max(wDisp, STR(":" << e.displayNum).size());
    wPid  = std::max(wPid, std::to_string(e.ownerPid).size());
    wXpid = std::max(wXpid, std::to_string(e.xServerPid).size());
    wVnc  = std::max(wVnc, (e.vncPort ? std::to_string(e.vncPort) : std::string("-")).size());
    wMode = std::max(wMode, e.mode.size());
    wJail = std::max(wJail, e.jailName.size());
  }

  // Header
  std::cout << rang::style::bold << std::left
            << std::setw(wDisp + 2) << "Display"
            << std::setw(wPid + 2) << "PID"
            << std::setw(wXpid + 2) << "Xpid"
            << std::setw(wVnc + 2) << "VNC"
            << std::setw(wMode + 2) << "Mode"
            << "Jail"
            << rang::style::reset << std::endl;

  // Rows
  for (auto &e : entries) {
    std::cout << std::left
              << std::setw(wDisp + 2) << STR(":" << e.displayNum)
              << std::setw(wPid + 2) << e.ownerPid
              << std::setw(wXpid + 2) << e.xServerPid
              << std::setw(wVnc + 2) << (e.vncPort ? std::to_string(e.vncPort) : std::string("-"))
              << std::setw(wMode + 2) << e.mode
              << e.jailName
              << std::endl;
  }

  std::cout << std::endl
            << entries.size() << " GUI session" << (entries.size() != 1 ? "s" : "")
            << "." << std::endl;
}

static bool guiList(const Args &args) {
  auto reg = Ctx::GuiRegistry::lock();
  auto entries = reg->getEntries();
  reg->unlock();

  if (args.guiJson)
    guiListJson(entries);
  else
    guiListTable(entries);
  return true;
}

// --- gui focus ---

static bool guiFocus(const Args &args) {
  auto reg = Ctx::GuiRegistry::lock();
  auto entries = reg->getEntries();
  auto *entry = reg->findByTarget(args.guiTarget);
  if (!entry) {
    reg->unlock();
    ERR("GUI session not found for target '" << args.guiTarget << "'")
  }
  auto e = *entry; // copy before unlock
  reg->unlock();

  if (e.mode != "nested") {
    ERR("'gui focus' is only supported for nested (Xephyr) sessions, but '" << e.jailName << "' uses mode '" << e.mode << "'")
  }

  // Use xdotool to find and activate the Xephyr window by PID
  try {
    auto windowId = Util::execCommandGetOutput(
      {CRATE_PATH_XDOTOOL, "search", "--pid", std::to_string(e.xServerPid)},
      "find Xephyr window");
    // windowId may have multiple lines; activate the first one
    std::istringstream is(windowId);
    std::string wid;
    if (std::getline(is, wid) && !wid.empty()) {
      Util::execCommand(
        {CRATE_PATH_XDOTOOL, "windowactivate", "--sync", wid},
        "activate window");
      std::cout << "Focused: " << e.jailName << " (display :" << e.displayNum << ")" << std::endl;
    } else {
      ERR("could not find X window for Xephyr PID " << e.xServerPid)
    }
  } catch (const Exception &ex) {
    ERR("failed to focus window: " << ex.what())
  }

  return true;
}

// --- gui attach ---

static bool guiAttach(const Args &args) {
  auto reg = Ctx::GuiRegistry::lock();
  auto entries = reg->getEntries();
  auto *entry = reg->findByTarget(args.guiTarget);
  if (!entry) {
    reg->unlock();
    ERR("GUI session not found for target '" << args.guiTarget << "'")
  }
  auto e = *entry;
  reg->unlock();

  if (e.vncPort == 0) {
    ERR("no VNC server running for '" << e.jailName << "' (mode=" << e.mode << ")")
  }

  std::cout << "Connecting VNC viewer to :" << e.displayNum
            << " (port " << e.vncPort << ")..." << std::endl;

  // Try known absolute paths for VNC viewers (CWE-426: no PATH search in setuid binary)
  auto host = STR("localhost:" << e.vncPort);
  struct stat st;
  const char *viewers[] = {
    "/usr/local/bin/vncviewer",    // tigervnc-viewer or tightvnc
    "/usr/local/bin/xvncviewer",   // xvncviewer
    nullptr
  };
  for (auto *v = viewers; *v; v++) {
    if (::stat(*v, &st) == 0) {
      ::execl(*v, *v, host.c_str(), nullptr);
      // execl only returns on error
    }
  }
  ERR("no VNC viewer found (install: pkg install tigervnc-viewer)")
  return false;
}

// --- gui url ---

static bool guiUrl(const Args &args) {
  auto reg = Ctx::GuiRegistry::lock();
  auto entries = reg->getEntries();
  auto *entry = reg->findByTarget(args.guiTarget);
  if (!entry) {
    reg->unlock();
    ERR("GUI session not found for target '" << args.guiTarget << "'")
  }
  auto e = *entry;
  reg->unlock();

  if (e.vncPort == 0)
    ERR("no VNC server running for '" << e.jailName << "'")

  // noVNC default: websockify on vncPort + 100 (e.g. 5910 -> 6010)
  unsigned wsPort = e.vncPort + 100;
  std::cout << "VNC:   vnc://localhost:" << e.vncPort << std::endl;
  std::cout << "noVNC: http://localhost:" << wsPort << "/vnc.html?autoconnect=true&port=" << wsPort << std::endl;

  return true;
}

// --- gui tile ---

static bool guiTile(const Args &) {
  auto reg = Ctx::GuiRegistry::lock();
  auto entries = reg->getEntries();
  reg->unlock();

  // Filter only nested (Xephyr) sessions
  std::vector<Ctx::GuiEntry> nested;
  for (auto &e : entries)
    if (e.mode == "nested")
      nested.push_back(e);

  if (nested.empty()) {
    std::cout << "No nested (Xephyr) GUI sessions to tile." << std::endl;
    return true;
  }

  // Get screen dimensions
  std::string screenGeom;
  try {
    screenGeom = Util::execCommandGetOutput(
      {CRATE_PATH_XDOTOOL, "getdisplaygeometry"},
      "get display geometry");
  } catch (...) {
    ERR("failed to get display geometry via xdotool")
  }

  unsigned screenW = 1920, screenH = 1080;
  std::istringstream gs(screenGeom);
  gs >> screenW >> screenH;

  // Calculate grid layout
  unsigned n = nested.size();
  unsigned cols = 1;
  while (cols * cols < n)
    cols++;
  unsigned rows = (n + cols - 1) / cols;
  unsigned tileW = screenW / cols;
  unsigned tileH = screenH / rows;

  unsigned idx = 0;
  for (auto &e : nested) {
    unsigned col = idx % cols;
    unsigned row = idx / cols;
    unsigned x = col * tileW;
    unsigned y = row * tileH;

    try {
      auto windowId = Util::execCommandGetOutput(
        {CRATE_PATH_XDOTOOL, "search", "--pid", std::to_string(e.xServerPid)},
        "find Xephyr window");
      std::istringstream is(windowId);
      std::string wid;
      if (std::getline(is, wid) && !wid.empty()) {
        Util::execCommand(
          {CRATE_PATH_XDOTOOL, "windowsize", wid,
           std::to_string(tileW), std::to_string(tileH)},
          "resize window");
        Util::execCommand(
          {CRATE_PATH_XDOTOOL, "windowmove", wid,
           std::to_string(x), std::to_string(y)},
          "move window");
      }
    } catch (...) {
      WARN("failed to tile window for " << e.jailName)
    }
    idx++;
  }

  std::cout << "Tiled " << nested.size() << " window"
            << (nested.size() != 1 ? "s" : "")
            << " in " << cols << "x" << rows << " grid." << std::endl;

  return true;
}

// --- gui screenshot ---

static bool guiScreenshot(const Args &args) {
  auto reg = Ctx::GuiRegistry::lock();
  auto entries = reg->getEntries();
  auto *entry = reg->findByTarget(args.guiTarget);
  if (!entry) {
    reg->unlock();
    ERR("GUI session not found for target '" << args.guiTarget << "'")
  }
  auto e = *entry;
  reg->unlock();

  auto dispStr = STR(":" << e.displayNum);
  auto outFile = args.guiOutput.empty()
    ? STR(e.jailName << "-screenshot.png")
    : args.guiOutput;
  auto xwdFile = STR("/tmp/crate-screenshot-" << e.displayNum << ".xwd");

  try {
    // Capture with xwd
    Util::execCommand(
      {CRATE_PATH_XWD, "-root", "-display", dispStr, "-out", xwdFile},
      "capture screenshot");
    // Convert xwd -> pnm -> png
    Util::execPipeline(
      {{CRATE_PATH_XWDTOPNM, xwdFile}, {CRATE_PATH_PNMTOPNG}},
      "convert screenshot", "", outFile);
    Util::Fs::unlink(xwdFile);
  } catch (const Exception &ex) {
    // Cleanup temp file
    if (Util::Fs::fileExists(xwdFile))
      Util::Fs::unlink(xwdFile);
    ERR("screenshot failed: " << ex.what())
  }

  std::cout << "Screenshot saved: " << outFile << std::endl;
  return true;
}

// --- gui resize ---

static bool guiResize(const Args &args) {
  auto reg = Ctx::GuiRegistry::lock();
  auto entries = reg->getEntries();
  auto *entry = reg->findByTarget(args.guiTarget);
  if (!entry) {
    reg->unlock();
    ERR("GUI session not found for target '" << args.guiTarget << "'")
  }
  auto e = *entry;
  reg->unlock();

  if (e.mode != "nested") {
    ERR("'gui resize' is only supported for nested (Xephyr) sessions")
  }

  // Parse resolution "WxH"
  auto xpos = args.guiResolution.find('x');
  if (xpos == std::string::npos)
    ERR("invalid resolution format '" << args.guiResolution << "' (expected WxH, e.g. 1920x1080)")

  auto wStr = args.guiResolution.substr(0, xpos);
  auto hStr = args.guiResolution.substr(xpos + 1);

  try {
    auto windowId = Util::execCommandGetOutput(
      {CRATE_PATH_XDOTOOL, "search", "--pid", std::to_string(e.xServerPid)},
      "find Xephyr window");
    std::istringstream is(windowId);
    std::string wid;
    if (std::getline(is, wid) && !wid.empty()) {
      Util::execCommand(
        {CRATE_PATH_XDOTOOL, "windowsize", wid, wStr, hStr},
        "resize Xephyr window");
      std::cout << "Resized " << e.jailName << " (display :" << e.displayNum
                << ") to " << args.guiResolution << std::endl;
    } else {
      ERR("could not find X window for Xephyr PID " << e.xServerPid)
    }
  } catch (const Exception &ex) {
    ERR("resize failed: " << ex.what())
  }

  return true;
}

// --- dispatch ---

bool guiCommand(const Args &args) {
  if (args.guiSubcmd == "list")
    return guiList(args);
  if (args.guiSubcmd == "focus")
    return guiFocus(args);
  if (args.guiSubcmd == "attach")
    return guiAttach(args);
  if (args.guiSubcmd == "url")
    return guiUrl(args);
  if (args.guiSubcmd == "tile")
    return guiTile(args);
  if (args.guiSubcmd == "screenshot")
    return guiScreenshot(args);
  if (args.guiSubcmd == "resize")
    return guiResize(args);

  ERR("unknown gui subcommand: " << args.guiSubcmd)
  return false;
}
