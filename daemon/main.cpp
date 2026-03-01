// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// crated — REST API daemon for remote container management.
// Listens on Unix socket (local) and TCP/TLS (remote).
// Delegates operations to libcrate.

#include "config.h"
#include "server.h"

#include "err.h"
#include "misc.h"
#include "util.h"

#include <rang.hpp>

#include <paths.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include <iostream>

static volatile sig_atomic_t g_running = 1;

static void signalHandler(int sig) {
  (void)sig;
  g_running = 0;
}

static void daemonize() {
  pid_t pid = ::fork();
  if (pid < 0)
    ERR2("crated", "fork failed: " << strerror(errno))
  if (pid > 0)
    ::_exit(0); // parent exits
  ::setsid();
  // Redirect stdin/stdout/stderr to /dev/null
  int devnull = ::open("/dev/null", O_RDWR);
  if (devnull >= 0) {
    ::dup2(devnull, STDIN_FILENO);
    ::dup2(devnull, STDOUT_FILENO);
    ::dup2(devnull, STDERR_FILENO);
    if (devnull > 2)
      ::close(devnull);
  }
}

static void writePidFile(const std::string &path) {
  auto pidStr = std::to_string(::getpid()) + "\n";
  Util::Fs::writeFile(pidStr, path);
}

int main(int argc, char **argv) {
  try {
    bool foreground = false;
    std::string configPath = "/usr/local/etc/crated.conf";

    for (int i = 1; i < argc; i++) {
      std::string arg = argv[i];
      if (arg == "-f" || arg == "--foreground")
        foreground = true;
      else if (arg == "-c" || arg == "--config") {
        if (i + 1 < argc)
          configPath = argv[++i];
      } else if (arg == "-h" || arg == "--help") {
        std::cout << "Usage: crated [-f] [-c config]\n"
                  << "  -f, --foreground  Run in foreground (don't daemonize)\n"
                  << "  -c, --config      Config file (default: /usr/local/etc/crated.conf)\n";
        return 0;
      }
    }

    // Must run as root (manages jails)
    if (::geteuid() != 0) {
      std::cerr << "crated must run as root" << std::endl;
      return 1;
    }

    // Load configuration
    Crated::Config config;
    if (Util::Fs::fileExists(configPath))
      config = Crated::Config::load(configPath);

    // Ensure /var/run/crate exists
    createJailsDirectoryIfNeeded();

    // Daemonize unless -f
    if (!foreground)
      daemonize();

    // Write PID file
    writePidFile("/var/run/crate/crated.pid");

    // Set up signal handlers
    ::signal(SIGINT, signalHandler);
    ::signal(SIGTERM, signalHandler);
    ::signal(SIGPIPE, SIG_IGN);

    // Start HTTP server
    Crated::Server server(config);
    server.start();

    std::cerr << "crated started";
    if (!config.unixSocket.empty())
      std::cerr << " unix=" << config.unixSocket;
    if (config.tcpPort != 0)
      std::cerr << " tcp=:" << config.tcpPort;
    std::cerr << std::endl;

    // Main loop — server runs in threads, we just wait for signals
    while (g_running)
      ::sleep(1);

    server.stop();
    ::unlink("/var/run/crate/crated.pid");

    return 0;
  } catch (const Exception &e) {
    std::cerr << "crated: " << e.what() << std::endl;
    return 1;
  } catch (const std::exception &e) {
    std::cerr << "crated: " << e.what() << std::endl;
    return 1;
  }
}
