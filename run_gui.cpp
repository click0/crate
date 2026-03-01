// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "run_gui.h"
#include "spec.h"
#include "gui_registry.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <errno.h>

#include <iostream>
#include <sstream>
#include <string>

#define ERR(msg...) ERR2("gui", msg)

namespace RunGui {

// Determine effective GUI mode from spec.
// Priority: gui.mode > x11.mode > auto-detect (nested if DISPLAY set, headless otherwise).
static std::string resolveGuiMode(const Spec &spec) {
  if (spec.guiOptions) {
    if (spec.guiOptions->mode == "auto") {
      auto *disp = ::getenv("DISPLAY");
      return disp ? "nested" : "headless";
    }
    return spec.guiOptions->mode;
  }
  if (spec.x11Options)
    return spec.x11Options->mode;
  return "shared";
}

// Determine effective resolution
static std::string resolveResolution(const Spec &spec) {
  if (spec.guiOptions && !spec.guiOptions->resolution.empty())
    return spec.guiOptions->resolution;
  if (spec.x11Options && !spec.x11Options->resolution.empty())
    return spec.x11Options->resolution;
  return "1280x720";
}

// Start x11vnc for a given display, return cleanup callback and set vncPort
static RunAtEnd startVnc(unsigned displayNum, unsigned &vncPort,
                         const Spec &spec, bool logProgress) {
  unsigned port = 5900 + displayNum;
  if (spec.guiOptions && spec.guiOptions->vncPort != 0)
    port = spec.guiOptions->vncPort;

  auto dispStr = STR(":" << displayNum);
  std::vector<std::string> vncArgs = {
    CRATE_PATH_X11VNC,
    "-display", dispStr,
    "-rfbport", std::to_string(port),
    "-shared", "-forever",
    "-nopw"
  };

  // Add password if configured
  if (spec.guiOptions && !spec.guiOptions->vncPassword.empty()) {
    // x11vnc -passwd <password> replaces -nopw
    vncArgs.pop_back(); // remove -nopw
    vncArgs.push_back("-passwd");
    vncArgs.push_back(spec.guiOptions->vncPassword);
  }

  if (logProgress)
    std::cerr << rang::fg::gray << "starting x11vnc on display " << dispStr
              << " port " << port << rang::style::reset << std::endl;

  pid_t vncPid = ::fork();
  if (vncPid == 0) {
    // Redirect stdout/stderr to /dev/null
    int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      ::dup2(devnull, STDOUT_FILENO);
      ::dup2(devnull, STDERR_FILENO);
      ::close(devnull);
    }
    // Build argv for execv
    std::vector<const char*> argv;
    for (auto &a : vncArgs)
      argv.push_back(a.c_str());
    argv.push_back(nullptr);
    ::execv(CRATE_PATH_X11VNC, const_cast<char* const*>(argv.data()));
    ::_exit(127);
  }
  if (vncPid == -1)
    ERR("failed to fork x11vnc: " << strerror(errno))

  vncPort = port;
  return RunAtEnd([vncPid, logProgress]() {
    if (logProgress)
      std::cerr << rang::fg::gray << "killing x11vnc pid=" << vncPid << rang::style::reset << std::endl;
    ::kill(vncPid, SIGTERM);
    int status;
    ::waitpid(vncPid, &status, 0);
  });
}

// Start websockify for noVNC
static RunAtEnd startWebsockify(unsigned vncPort, bool logProgress) {
  unsigned wsPort = vncPort + 100; // e.g. 5910 -> 6010
  auto target = STR("localhost:" << vncPort);

  if (logProgress)
    std::cerr << rang::fg::gray << "starting websockify on port " << wsPort
              << " -> " << target << rang::style::reset << std::endl;

  pid_t wsPid = ::fork();
  if (wsPid == 0) {
    int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      ::dup2(devnull, STDOUT_FILENO);
      ::dup2(devnull, STDERR_FILENO);
      ::close(devnull);
    }
    ::execl(CRATE_PATH_WEBSOCKIFY, "websockify",
            std::to_string(wsPort).c_str(), target.c_str(),
            nullptr);
    ::_exit(127);
  }
  if (wsPid == -1)
    ERR("failed to fork websockify: " << strerror(errno))

  return RunAtEnd([wsPid, logProgress]() {
    if (logProgress)
      std::cerr << rang::fg::gray << "killing websockify pid=" << wsPid << rang::style::reset << std::endl;
    ::kill(wsPid, SIGTERM);
    int status;
    ::waitpid(wsPid, &status, 0);
  });
}

RunAtEnd setupX11(const Spec &spec, const std::string &jailPath,
                  const std::string &jailXname,
                  std::list<std::unique_ptr<Mount>> &mounts,
                  std::function<void(const std::string&, const std::string&)> setJailEnv,
                  bool logProgress) {
  if (!spec.optionExists("x11") && !spec.guiOptions)
    return RunAtEnd();

  auto J = [&jailPath](auto subdir) { return STR(jailPath << subdir); };
  auto mount = [&mounts](Mount *m) {
    mounts.push_front(std::unique_ptr<Mount>(m));
    m->mount();
  };

  auto guiMode = resolveGuiMode(spec);
  auto resolution = resolveResolution(spec);

  if (guiMode == "none") {
    if (logProgress)
      std::cerr << rang::fg::gray << "x11 option (mode=none): no X11 access" << rang::style::reset << std::endl;
    return RunAtEnd();
  }

  // Headless mode: Xvfb (no physical display needed)
  if (guiMode == "headless") {
    // Allocate display number from the GUI registry
    auto reg = Ctx::GuiRegistry::lock();
    unsigned dispNum = reg->allocateDisplay(::getpid());
    reg->unlock();

    auto dispStr = STR(":" << dispNum);
    auto screenSpec = STR(resolution << "x24"); // 24-bit color depth

    if (logProgress)
      std::cerr << rang::fg::gray << "headless mode: starting Xvfb at " << resolution
                << " on display " << dispStr << rang::style::reset << std::endl;

    pid_t xvfbPid = ::fork();
    if (xvfbPid == 0) {
      ::execl(CRATE_PATH_XVFB, "Xvfb", dispStr.c_str(),
              "-screen", "0", screenSpec.c_str(),
              "-ac", "-nolisten", "tcp",
              nullptr);
      ::_exit(127);
    }
    if (xvfbPid == -1)
      ERR("failed to fork Xvfb: " << strerror(errno))

    ::usleep(300000); // let Xvfb initialize

    Util::Fs::mkdir(J("/tmp/.X11-unix"), 01777);
    mount(new Mount("nullfs", J("/tmp/.X11-unix"), "/tmp/.X11-unix", MNT_IGNORE));
    setJailEnv("DISPLAY", dispStr);

    // Start x11vnc if gui.vnc=true or if gui: section exists with vnc enabled
    unsigned vncPort = 0;
    RunAtEnd vncCleanup;
    RunAtEnd wsCleanup;
    bool wantVnc = spec.guiOptions && spec.guiOptions->vnc;
    bool wantNoVnc = spec.guiOptions && spec.guiOptions->novnc;

    if (wantVnc) {
      ::usleep(200000); // give Xvfb time to create the socket
      vncCleanup = startVnc(dispNum, vncPort, spec, logProgress);
    }
    if (wantNoVnc && vncPort != 0) {
      ::usleep(200000); // give x11vnc time to start
      wsCleanup = startWebsockify(vncPort, logProgress);
    }

    // Register in GUI registry
    {
      auto regW = Ctx::GuiRegistry::lock();
      Ctx::GuiEntry entry;
      entry.ownerPid = ::getpid();
      entry.displayNum = dispNum;
      entry.xServerPid = xvfbPid;
      entry.vncPort = vncPort;
      entry.mode = "headless";
      entry.jailName = jailXname;
      regW->registerEntry(entry);
      regW->unlock();
    }

    if (vncPort != 0) {
      std::cerr << rang::fg::cyan << "VNC available on port " << vncPort;
      if (wantNoVnc)
        std::cerr << ", noVNC on port " << (vncPort + 100);
      std::cerr << rang::style::reset << std::endl;
    }

    auto ownerPid = ::getpid();
    return RunAtEnd([xvfbPid, ownerPid, logProgress,
                     vncCleanup = std::make_shared<RunAtEnd>(std::move(vncCleanup)),
                     wsCleanup = std::make_shared<RunAtEnd>(std::move(wsCleanup))]() {
      // Unregister from GUI registry
      try {
        auto reg = Ctx::GuiRegistry::lock();
        reg->unregisterEntry(ownerPid);
        reg->unlock();
      } catch (...) {}

      // Stop websockify, then VNC, then Xvfb
      wsCleanup->doNow();
      vncCleanup->doNow();

      if (logProgress)
        std::cerr << rang::fg::gray << "killing Xvfb pid=" << xvfbPid << rang::style::reset << std::endl;
      ::kill(xvfbPid, SIGTERM);
      int status;
      ::waitpid(xvfbPid, &status, 0);
    });
  }

  // Nested mode: Xephyr (requires host DISPLAY)
  if (guiMode == "nested") {
    auto *hostDisplay = ::getenv("DISPLAY");
    if (hostDisplay == nullptr)
      ERR("DISPLAY environment variable is not set (needed for Xephyr host connection)")

    // Allocate display number from the GUI registry
    auto reg = Ctx::GuiRegistry::lock();
    unsigned dispNum = reg->allocateDisplay(::getpid());
    reg->unlock();

    auto dispStr = STR(":" << dispNum);
    if (logProgress)
      std::cerr << rang::fg::gray << "x11 nested mode: starting Xephyr at " << resolution
                << " on display " << dispStr << rang::style::reset << std::endl;

    pid_t xephyrPid = ::fork();
    if (xephyrPid == 0) {
      ::execl(CRATE_PATH_XEPHYR, "Xephyr", dispStr.c_str(),
              "-screen", resolution.c_str(),
              "-resizeable", "-no-host-grab",
              nullptr);
      ::_exit(127);
    }
    if (xephyrPid == -1)
      ERR("failed to fork Xephyr: " << strerror(errno))

    ::usleep(500000);
    Util::Fs::mkdir(J("/tmp/.X11-unix"), 01777);
    mount(new Mount("nullfs", J("/tmp/.X11-unix"), "/tmp/.X11-unix", MNT_IGNORE));
    setJailEnv("DISPLAY", dispStr);

    // Register in GUI registry
    {
      auto regW = Ctx::GuiRegistry::lock();
      Ctx::GuiEntry entry;
      entry.ownerPid = ::getpid();
      entry.displayNum = dispNum;
      entry.xServerPid = xephyrPid;
      entry.vncPort = 0;
      entry.mode = "nested";
      entry.jailName = jailXname;
      regW->registerEntry(entry);
      regW->unlock();
    }

    auto ownerPid = ::getpid();
    return RunAtEnd([xephyrPid, ownerPid, logProgress]() {
      // Unregister from GUI registry
      try {
        auto reg = Ctx::GuiRegistry::lock();
        reg->unregisterEntry(ownerPid);
        reg->unlock();
      } catch (...) {}

      if (logProgress)
        std::cerr << rang::fg::gray << "killing Xephyr pid=" << xephyrPid << rang::style::reset << std::endl;
      ::kill(xephyrPid, SIGTERM);
      int status;
      ::waitpid(xephyrPid, &status, 0);
    });
  }

  // Shared mode (default): mount host X11 socket into jail
  if (logProgress)
    std::cerr << rang::fg::gray << "x11 option (mode=shared): mount the X11 socket in jail" << rang::style::reset << std::endl;
  Util::Fs::mkdir(J("/tmp/.X11-unix"), 01777);
  mount(new Mount("nullfs", J("/tmp/.X11-unix"), "/tmp/.X11-unix", MNT_IGNORE));
  auto *display = ::getenv("DISPLAY");
  if (display == nullptr)
    ERR("DISPLAY environment variable is not set")
  setJailEnv("DISPLAY", display);

  // Register shared mode in GUI registry (for tracking)
  {
    auto regW = Ctx::GuiRegistry::lock();
    Ctx::GuiEntry entry;
    entry.ownerPid = ::getpid();
    entry.displayNum = 0; // shared uses host display
    entry.xServerPid = 0;
    entry.vncPort = 0;
    entry.mode = "shared";
    entry.jailName = jailXname;
    regW->registerEntry(entry);
    regW->unlock();
  }

  auto ownerPid = ::getpid();
  return RunAtEnd([ownerPid]() {
    try {
      auto reg = Ctx::GuiRegistry::lock();
      reg->unregisterEntry(ownerPid);
      reg->unlock();
    } catch (...) {}
  });
}

RunAtEnd setupClipboard(const Spec &spec, const std::string &jailXname,
                        const std::string &jidStr, bool logProgress) {
  if (!spec.clipboardOptions || spec.clipboardOptions->mode == "none")
    return RunAtEnd();

  // Log clipboard isolation mode
  if (spec.clipboardOptions->mode == "isolated") {
    std::string x11Mode = spec.x11Options ? spec.x11Options->mode : "shared";
    if (x11Mode == "nested") {
      if (logProgress)
        std::cerr << rang::fg::gray << "clipboard isolation: active (via nested X11)" << rang::style::reset << std::endl;
    } else {
      if (logProgress)
        std::cerr << rang::fg::gray << "clipboard isolation: requested but x11 is not nested — limited isolation" << rang::style::reset << std::endl;
    }
  }

  auto &dir = spec.clipboardOptions->direction;
  std::string x11Mode = spec.x11Options ? spec.x11Options->mode : "shared";

  if (spec.clipboardOptions->mode == "isolated" && x11Mode == "nested") {
    if (logProgress)
      std::cerr << rang::fg::gray << "clipboard isolation via nested X11 (automatic)" << rang::style::reset << std::endl;
    return RunAtEnd();
  }

  if (dir == "none")
    return RunAtEnd();

  // Start xclip proxy for controlled clipboard sharing
  std::ostringstream proxyScript;
  proxyScript << "#!/bin/sh" << std::endl;
  proxyScript << "while true; do" << std::endl;
  if (dir == "in" || dir == "both")
    proxyScript << "  xclip -selection clipboard -o 2>/dev/null | jexec " << jidStr << " xclip -selection clipboard -i 2>/dev/null" << std::endl;
  if (dir == "out" || dir == "both")
    proxyScript << "  jexec " << jidStr << " xclip -selection clipboard -o 2>/dev/null | xclip -selection clipboard -i 2>/dev/null" << std::endl;
  proxyScript << "  sleep 1" << std::endl;
  proxyScript << "done" << std::endl;

  auto proxyFile = STR("/tmp/crate-clipboard-" << jailXname << ".sh");
  Util::Fs::writeFile(proxyScript.str(), proxyFile);
  Util::Fs::chmod(proxyFile, 0700);
  pid_t clipPid = ::fork();
  if (clipPid == 0) {
    ::execl(CRATE_PATH_SH, CRATE_PATH_SH, proxyFile.c_str(), nullptr);
    ::_exit(127);
  }
  if (clipPid > 0) {
    if (logProgress)
      std::cerr << rang::fg::gray << "clipboard proxy started (direction=" << dir << ")" << rang::style::reset << std::endl;
    return RunAtEnd([clipPid, proxyFile]() {
      ::kill(clipPid, SIGTERM);
      int status;
      ::waitpid(clipPid, &status, 0);
      Util::Fs::unlink(proxyFile);
    });
  }

  return RunAtEnd();
}

void setupDbus(const Spec &spec, const std::string &jailPath,
               std::function<void(const std::string&, const std::string&)> setJailEnv,
               bool logProgress) {
  if (!spec.dbusOptions)
    return;

  auto J = [&jailPath](auto subdir) { return STR(jailPath << subdir); };
  auto writeFileInJail = [&J](auto str, auto file) { Util::Fs::writeFile(str, J(file)); };

  if (spec.dbusOptions->sessionBus) {
    if (logProgress)
      std::cerr << rang::fg::gray << "configuring D-Bus session bus inside jail" << rang::style::reset << std::endl;
    std::ostringstream policy;
    policy << "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN\"" << std::endl;
    policy << " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">" << std::endl;
    policy << "<busconfig>" << std::endl;
    policy << "  <type>custom</type>" << std::endl;
    policy << "  <listen>unix:path=/var/run/dbus/session_bus</listen>" << std::endl;
    policy << "  <auth>EXTERNAL</auth>" << std::endl;
    policy << "  <policy context=\"default\">" << std::endl;
    policy << "    <allow send_destination=\"*\" eavesdrop=\"false\"/>" << std::endl;
    policy << "    <allow receive_sender=\"*\"/>" << std::endl;
    for (auto &name : spec.dbusOptions->allowOwn)
      policy << "    <allow own=\"" << name << "\"/>" << std::endl;
    for (auto &name : spec.dbusOptions->denySend)
      policy << "    <deny send_destination=\"" << name << "\"/>" << std::endl;
    policy << "  </policy>" << std::endl;
    policy << "</busconfig>" << std::endl;
    Util::Fs::mkdir(J("/usr/local/etc/dbus-1"), 0755);
    writeFileInJail(policy.str(), "/usr/local/etc/dbus-1/session-local.conf");
    Util::Fs::mkdir(J("/var/run/dbus"), 0755);
    setJailEnv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/var/run/dbus/session_bus");
    if (logProgress)
      std::cerr << rang::fg::gray << "D-Bus session bus configured" << rang::style::reset << std::endl;
  }
  if (!spec.dbusOptions->systemBus) {
    if (logProgress)
      std::cerr << rang::fg::gray << "D-Bus system bus disabled (not mounting host socket)" << rang::style::reset << std::endl;
  }
}

void copyX11Auth(const Spec &spec, const std::string &jailPath,
                 const std::string &homeDir, uid_t uid, gid_t gid) {
  if (!spec.optionExists("x11") && !spec.guiOptions)
    return;

  auto J = [&jailPath](auto subdir) { return STR(jailPath << subdir); };

  bool skipX11Auth = (spec.x11Options && spec.x11Options->mode == "none") ||
                     (spec.clipboardOptions && spec.clipboardOptions->mode == "none" &&
                      spec.x11Options && spec.x11Options->mode != "nested");
  // headless mode doesn't need host X auth
  if (spec.guiOptions && spec.guiOptions->mode == "headless")
    skipX11Auth = true;
  if (skipX11Auth)
    return;

  for (auto &file : {STR(homeDir << "/.Xauthority"), STR(homeDir << "/.ICEauthority")})
    if (Util::Fs::fileExists(file)) {
      Util::Fs::copyFile(file, J(file));
      Util::Fs::chown(J(file), uid, gid);
    }
}

}
