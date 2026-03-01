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
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <errno.h>

#include <iostream>
#include <sstream>
#include <string>

#define ERR(msg...) ERR2("gui", msg)

namespace RunGui {

// Check if a required external tool exists, abort with helpful message if not
static void requireTool(const char *path, const char *pkgHint) {
  struct stat st;
  if (::stat(path, &st) != 0)
    ERR("required tool not found: " << path << " (install: pkg install " << pkgHint << ")")
}

// Wait for X socket /tmp/.X11-unix/X<N> to appear, with timeout
static bool waitForXSocket(unsigned displayNum, unsigned timeoutMs = 5000) {
  auto socketPath = STR("/tmp/.X11-unix/X" << displayNum);
  unsigned elapsed = 0;
  unsigned step = 50000; // 50ms
  while (elapsed < timeoutMs * 1000) {
    struct stat st;
    if (::stat(socketPath.c_str(), &st) == 0)
      return true;
    ::usleep(step);
    elapsed += step;
  }
  return false;
}

// Check if a TCP port is available (not in use)
static bool isPortAvailable(unsigned port) {
  int sock = ::socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return false;
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int result = ::bind(sock, (struct sockaddr*)&addr, sizeof(addr));
  ::close(sock);
  return result == 0;
}

// Find an available VNC port starting from preferred
static unsigned findAvailablePort(unsigned preferred) {
  for (unsigned p = preferred; p < preferred + 100; p++)
    if (isPortAvailable(p))
      return p;
  return preferred; // fall back, let x11vnc report the error
}

// Determine effective GUI mode from spec.
// Priority: gui.mode > x11.mode > auto-detect.
// "auto" logic: if GPU detected -> gpu, elif DISPLAY set -> nested, else headless
static std::string resolveGuiMode(const Spec &spec) {
  if (spec.guiOptions) {
    if (spec.guiOptions->mode == "auto") {
      // Check for GPU: try to detect via sysctl or /dev/dri
      struct stat st;
      bool hasGpu = (::stat("/dev/dri/card0", &st) == 0) ||
                    (::stat("/dev/nvidia0", &st) == 0);
      if (hasGpu && ::getenv("DISPLAY") == nullptr)
        return "gpu";
      return ::getenv("DISPLAY") ? "nested" : "headless";
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

// Generate xorg.conf for headless GPU mode
static std::string generateGpuXorgConf(unsigned displayNum,
                                        const std::string &resolution,
                                        const std::string &gpuDriver,
                                        const std::string &gpuDevice) {
  // Parse WxH
  auto xpos = resolution.find('x');
  auto width = (xpos != std::string::npos) ? resolution.substr(0, xpos) : "1280";
  auto height = (xpos != std::string::npos) ? resolution.substr(xpos + 1) : "720";

  // Determine effective driver
  auto driver = gpuDriver.empty() ? std::string("dummy") : gpuDriver;

  std::ostringstream conf;

  // Device section
  conf << "Section \"Device\"" << std::endl;
  conf << "    Identifier \"GPU0\"" << std::endl;
  conf << "    Driver     \"" << driver << "\"" << std::endl;
  if (!gpuDevice.empty())
    conf << "    BusID      \"" << gpuDevice << "\"" << std::endl;
  // NVIDIA headless options
  if (driver == "nvidia") {
    conf << "    Option     \"AllowEmptyInitialConfiguration\" \"True\"" << std::endl;
    conf << "    Option     \"ConnectedMonitor\" \"DFP-0\"" << std::endl;
    conf << "    Option     \"CustomEDID\" \"DFP-0:/usr/local/share/crate/edid/1080p.bin\"" << std::endl;
  }
  conf << "EndSection" << std::endl;
  conf << std::endl;

  // Monitor section (virtual)
  conf << "Section \"Monitor\"" << std::endl;
  conf << "    Identifier \"Monitor0\"" << std::endl;
  conf << "    HorizSync   28.0-80.0" << std::endl;
  conf << "    VertRefresh  48.0-75.0" << std::endl;
  conf << "    Modeline \"" << resolution << "\" "
       << (width == "1920" ? "148.50" : width == "1280" ? "74.25" : "108.00")
       << " " << width << " "
       << (width == "1920" ? "2008 2052 2200" : width == "1280" ? "1390 1420 1650" : "1328 1440 1688")
       << " " << height << " "
       << (height == "1080" ? "1084 1089 1125" : height == "720" ? "725 730 750" : "1025 1028 1066")
       << " +hsync +vsync" << std::endl;
  conf << "EndSection" << std::endl;
  conf << std::endl;

  // Screen section
  conf << "Section \"Screen\"" << std::endl;
  conf << "    Identifier \"Screen0\"" << std::endl;
  conf << "    Device     \"GPU0\"" << std::endl;
  conf << "    Monitor    \"Monitor0\"" << std::endl;
  conf << "    DefaultDepth 24" << std::endl;
  conf << "    SubSection \"Display\"" << std::endl;
  conf << "        Depth      24" << std::endl;
  conf << "        Modes      \"" << resolution << "\"" << std::endl;
  conf << "        Virtual    " << width << " " << height << std::endl;
  conf << "    EndSubSection" << std::endl;
  conf << "EndSection" << std::endl;
  conf << std::endl;

  // ServerLayout
  conf << "Section \"ServerLayout\"" << std::endl;
  conf << "    Identifier \"Layout0\"" << std::endl;
  conf << "    Screen 0   \"Screen0\"" << std::endl;
  conf << "    Option     \"AllowMouseOpenFail\" \"true\"" << std::endl;
  conf << "    Option     \"AutoAddDevices\" \"false\"" << std::endl;
  conf << "    Option     \"AutoAddGPU\" \"false\"" << std::endl;
  conf << "EndSection" << std::endl;
  conf << std::endl;

  // ServerFlags
  conf << "Section \"ServerFlags\"" << std::endl;
  conf << "    Option \"DontVTSwitch\" \"true\"" << std::endl;
  conf << "    Option \"AllowMouseOpenFail\" \"true\"" << std::endl;
  conf << "    Option \"PciForceNone\" \"true\"" << std::endl;
  conf << "    Option \"AutoEnableDevices\" \"false\"" << std::endl;
  conf << "    Option \"AutoAddDevices\" \"false\"" << std::endl;
  conf << "EndSection" << std::endl;

  return conf.str();
}

// Start x11vnc for a given display, return cleanup callback and set vncPort
static RunAtEnd startVnc(unsigned displayNum, unsigned &vncPort,
                         const Spec &spec, bool logProgress) {
  requireTool(CRATE_PATH_X11VNC, "x11vnc");

  unsigned port = 5900 + displayNum;
  if (spec.guiOptions && spec.guiOptions->vncPort != 0)
    port = spec.guiOptions->vncPort;

  // Find an available port
  port = findAvailablePort(port);

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
    vncArgs.pop_back(); // remove -nopw
    vncArgs.push_back("-passwd");
    vncArgs.push_back(spec.guiOptions->vncPassword);
  }

  if (logProgress)
    std::cerr << rang::fg::gray << "starting x11vnc on display " << dispStr
              << " port " << port << rang::style::reset << std::endl;

  pid_t vncPid = ::fork();
  if (vncPid == 0) {
    int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      ::dup2(devnull, STDOUT_FILENO);
      ::dup2(devnull, STDERR_FILENO);
      ::close(devnull);
    }
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
  requireTool(CRATE_PATH_WEBSOCKIFY, "py311-websockify");

  unsigned wsPort = vncPort + 100; // e.g. 5910 -> 6010
  wsPort = findAvailablePort(wsPort);
  auto target = STR("localhost:" << vncPort);

  // Detect noVNC web directory
  std::string webDir;
  struct stat st;
  if (::stat("/usr/local/share/novnc", &st) == 0)
    webDir = "/usr/local/share/novnc";
  else if (::stat("/usr/local/share/noVNC", &st) == 0)
    webDir = "/usr/local/share/noVNC";

  if (logProgress) {
    std::cerr << rang::fg::gray << "starting websockify on port " << wsPort
              << " -> " << target;
    if (!webDir.empty())
      std::cerr << " (web: " << webDir << ")";
    std::cerr << rang::style::reset << std::endl;
  }

  pid_t wsPid = ::fork();
  if (wsPid == 0) {
    int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      ::dup2(devnull, STDOUT_FILENO);
      ::dup2(devnull, STDERR_FILENO);
      ::close(devnull);
    }
    if (!webDir.empty()) {
      auto webArg = STR("--web=" << webDir);
      ::execl(CRATE_PATH_WEBSOCKIFY, "websockify",
              webArg.c_str(),
              std::to_string(wsPort).c_str(), target.c_str(),
              nullptr);
    } else {
      ::execl(CRATE_PATH_WEBSOCKIFY, "websockify",
              std::to_string(wsPort).c_str(), target.c_str(),
              nullptr);
    }
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

// Common helper: start VNC + websockify, register entry, return cleanup
static RunAtEnd setupVncAndRegister(unsigned dispNum, pid_t xServerPid,
                                     const std::string &mode,
                                     const std::string &jailXname,
                                     const std::string &jailPath,
                                     std::list<std::unique_ptr<Mount>> &mounts,
                                     std::function<void(const std::string&, const std::string&)> setJailEnv,
                                     const Spec &spec, bool logProgress) {
  auto J = [&jailPath](auto subdir) { return STR(jailPath << subdir); };
  auto mount = [&mounts](Mount *m) {
    mounts.push_front(std::unique_ptr<Mount>(m));
    m->mount();
  };

  auto dispStr = STR(":" << dispNum);
  Util::Fs::mkdir(J("/tmp/.X11-unix"), 01777);
  mount(new Mount("nullfs", J("/tmp/.X11-unix"), "/tmp/.X11-unix", MNT_IGNORE));
  setJailEnv("DISPLAY", dispStr);

  unsigned vncPort = 0;
  RunAtEnd vncCleanup;
  RunAtEnd wsCleanup;
  bool wantVnc = spec.guiOptions && spec.guiOptions->vnc;
  bool wantNoVnc = spec.guiOptions && spec.guiOptions->novnc;

  if (wantVnc) {
    // Wait for X socket to appear before starting VNC
    if (!waitForXSocket(dispNum, 5000))
      WARN("X socket /tmp/.X11-unix/X" << dispNum << " not found after 5s, trying x11vnc anyway")
    vncCleanup = startVnc(dispNum, vncPort, spec, logProgress);
  }
  if (wantNoVnc && vncPort != 0) {
    ::usleep(200000); // x11vnc needs a moment to bind its port
    wsCleanup = startWebsockify(vncPort, logProgress);
  }

  // Register in GUI registry
  {
    auto regW = Ctx::GuiRegistry::lock();
    Ctx::GuiEntry entry;
    entry.ownerPid = ::getpid();
    entry.displayNum = dispNum;
    entry.xServerPid = xServerPid;
    entry.vncPort = vncPort;
    entry.mode = mode;
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
  return RunAtEnd([xServerPid, ownerPid, logProgress, mode,
                   vncCleanup = std::make_shared<RunAtEnd>(std::move(vncCleanup)),
                   wsCleanup = std::make_shared<RunAtEnd>(std::move(wsCleanup))]() {
    // Unregister from GUI registry
    try {
      auto reg = Ctx::GuiRegistry::lock();
      reg->unregisterEntry(ownerPid);
      reg->unlock();
    } catch (...) {}

    wsCleanup->doNow();
    vncCleanup->doNow();

    if (logProgress)
      std::cerr << rang::fg::gray << "killing " << mode << " X server pid=" << xServerPid << rang::style::reset << std::endl;
    ::kill(xServerPid, SIGTERM);
    int status;
    ::waitpid(xServerPid, &status, 0);
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

  // GPU mode: Xorg with real GPU driver in headless configuration
  if (guiMode == "gpu") {
    requireTool(CRATE_PATH_XORG, "xorg-server");

    auto reg = Ctx::GuiRegistry::lock();
    unsigned dispNum = reg->allocateDisplay(::getpid());
    reg->unlock();

    auto dispStr = STR(":" << dispNum);

    // Determine GPU driver and device
    auto gpuDriver = (spec.guiOptions) ? spec.guiOptions->gpuDriver : std::string();
    auto gpuDevice = (spec.guiOptions) ? spec.guiOptions->gpuDevice : std::string();

    // Auto-detect GPU driver if not specified
    if (gpuDriver.empty()) {
      struct stat st;
      if (::stat("/dev/nvidia0", &st) == 0)
        gpuDriver = "nvidia";
      else if (::stat("/dev/dri/card0", &st) == 0)
        gpuDriver = "amdgpu"; // could also be intel, but amdgpu is more common on servers
      else
        gpuDriver = "dummy"; // fallback to dummy (no GPU acceleration)
    }

    // Generate temporary xorg.conf
    auto xorgConf = generateGpuXorgConf(dispNum, resolution, gpuDriver, gpuDevice);
    auto confPath = STR("/tmp/crate-xorg-" << dispNum << ".conf");
    Util::Fs::writeFile(xorgConf, confPath);

    if (logProgress) {
      std::cerr << rang::fg::gray << "gpu mode: starting Xorg at " << resolution
                << " on display " << dispStr << " (driver: " << gpuDriver;
      if (!gpuDevice.empty())
        std::cerr << ", device: " << gpuDevice;
      std::cerr << ")" << rang::style::reset << std::endl;
    }

    pid_t xorgPid = ::fork();
    if (xorgPid == 0) {
      ::execl(CRATE_PATH_XORG, "Xorg", dispStr.c_str(),
              "-config", confPath.c_str(),
              "-noreset", "-nolisten", "tcp",
              nullptr);
      ::_exit(127);
    }
    if (xorgPid == -1) {
      Util::Fs::unlink(confPath);
      ERR("failed to fork Xorg: " << strerror(errno))
    }

    // Wait for X socket
    if (!waitForXSocket(dispNum, 10000)) {
      ::kill(xorgPid, SIGTERM);
      int status;
      ::waitpid(xorgPid, &status, 0);
      Util::Fs::unlink(confPath);
      ERR("Xorg failed to start within 10s on display " << dispStr
          << " (check /var/log/Xorg." << dispNum << ".log)")
    }

    auto cleanup = setupVncAndRegister(dispNum, xorgPid, "gpu", jailXname,
                                        jailPath, mounts, setJailEnv, spec, logProgress);
    // Wrap cleanup to also remove conf file
    return RunAtEnd([cleanup = std::make_shared<RunAtEnd>(std::move(cleanup)), confPath]() {
      cleanup->doNow();
      Util::Fs::unlink(confPath);
    });
  }

  // Headless mode: Xvfb (software rendering, no GPU)
  if (guiMode == "headless") {
    requireTool(CRATE_PATH_XVFB, "xorg-vfbserver");

    auto reg = Ctx::GuiRegistry::lock();
    unsigned dispNum = reg->allocateDisplay(::getpid());
    reg->unlock();

    auto dispStr = STR(":" << dispNum);
    auto screenSpec = STR(resolution << "x24");

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

    // Wait for X socket instead of fixed sleep
    if (!waitForXSocket(dispNum, 5000)) {
      ::kill(xvfbPid, SIGTERM);
      int status;
      ::waitpid(xvfbPid, &status, 0);
      ERR("Xvfb failed to start within 5s on display " << dispStr)
    }

    return setupVncAndRegister(dispNum, xvfbPid, "headless", jailXname,
                                jailPath, mounts, setJailEnv, spec, logProgress);
  }

  // Nested mode: Xephyr (requires host DISPLAY)
  if (guiMode == "nested") {
    requireTool(CRATE_PATH_XEPHYR, "xorg-server-Xephyr");

    auto *hostDisplay = ::getenv("DISPLAY");
    if (hostDisplay == nullptr)
      ERR("DISPLAY environment variable is not set (needed for Xephyr host connection)")

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

    if (!waitForXSocket(dispNum, 5000)) {
      ::kill(xephyrPid, SIGTERM);
      int status;
      ::waitpid(xephyrPid, &status, 0);
      ERR("Xephyr failed to start within 5s on display " << dispStr)
    }

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
    entry.displayNum = 0;
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
  // headless/gpu modes don't need host X auth
  if (spec.guiOptions && (spec.guiOptions->mode == "headless" || spec.guiOptions->mode == "gpu"))
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
