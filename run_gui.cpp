// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include "run_gui.h"
#include "spec.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <errno.h>

#include <iostream>
#include <sstream>

#define ERR(msg...) ERR2("gui", msg)

namespace RunGui {

RunAtEnd setupX11(const Spec &spec, const std::string &jailPath,
                  const std::string &jailXname,
                  std::list<std::unique_ptr<Mount>> &mounts,
                  std::function<void(const std::string&, const std::string&)> setJailEnv,
                  bool logProgress) {
  if (!spec.optionExists("x11"))
    return RunAtEnd();

  auto J = [&jailPath](auto subdir) { return STR(jailPath << subdir); };
  auto mount = [&mounts](Mount *m) {
    mounts.push_front(std::unique_ptr<Mount>(m));
    m->mount();
  };

  std::string x11Mode = "shared";
  if (spec.x11Options)
    x11Mode = spec.x11Options->mode;

  if (x11Mode == "none") {
    if (logProgress)
      std::cerr << rang::fg::gray << "x11 option (mode=none): no X11 access" << rang::style::reset << std::endl;
    return RunAtEnd();
  }

  if (x11Mode == "nested") {
    auto resolution = (spec.x11Options && !spec.x11Options->resolution.empty())
                      ? spec.x11Options->resolution : std::string("1280x720");
    auto *hostDisplay = ::getenv("DISPLAY");
    if (hostDisplay == nullptr)
      ERR("DISPLAY environment variable is not set (needed for Xephyr host connection)")
    unsigned dispNum = 99 + (::getpid() % 100);
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
    return RunAtEnd([xephyrPid, logProgress]() {
      if (logProgress)
        std::cerr << rang::fg::gray << "killing Xephyr pid=" << xephyrPid << rang::style::reset << std::endl;
      ::kill(xephyrPid, SIGTERM);
      int status;
      ::waitpid(xephyrPid, &status, 0);
    });
  }

  // Shared mode (default)
  if (logProgress)
    std::cerr << rang::fg::gray << "x11 option (mode=shared): mount the X11 socket in jail" << rang::style::reset << std::endl;
  Util::Fs::mkdir(J("/tmp/.X11-unix"), 01777);
  mount(new Mount("nullfs", J("/tmp/.X11-unix"), "/tmp/.X11-unix", MNT_IGNORE));
  auto *display = ::getenv("DISPLAY");
  if (display == nullptr)
    ERR("DISPLAY environment variable is not set")
  setJailEnv("DISPLAY", display);
  return RunAtEnd();
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
  if (!spec.optionExists("x11"))
    return;

  auto J = [&jailPath](auto subdir) { return STR(jailPath << subdir); };

  bool skipX11Auth = (spec.x11Options && spec.x11Options->mode == "none") ||
                     (spec.clipboardOptions && spec.clipboardOptions->mode == "none" &&
                      spec.x11Options && spec.x11Options->mode != "nested");
  if (skipX11Auth)
    return;

  for (auto &file : {STR(homeDir << "/.Xauthority"), STR(homeDir << "/.ICEauthority")})
    if (Util::Fs::fileExists(file)) {
      Util::Fs::copyFile(file, J(file));
      Util::Fs::chown(J(file), uid, gid);
    }
}

}
