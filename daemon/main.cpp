// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// crated — REST API daemon for remote container management.
// Listens on Unix socket (local) and TCP/TLS (remote).
// Delegates operations to libcrate.

#include "config.h"
#include "server.h"
#include "ws_console.h"
#include "control_socket.h"
#include "privops_handlers.h"
#include "privops_listener.h"

#include "../lib/jid_owner_registry.h"

#include "err.h"
#include "misc.h"
#include "util.h"

#include <rang.hpp>

#include <fcntl.h>
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

    // Start WebSocket console listener (opt-in via config.consoleWsPort).
    bool wsStarted = Crated::WsConsole::start(config);

    // Start control sockets (opt-in: empty config.controlSockets = none).
    Crated::ControlSocketsManager controlSockets(config);
    int csStarted = controlSockets.start();

    // 0.9.14: privops listener (opt-in via privops_socket: in config).
    // 0.9.29: register umbrella RCTL rules with the privops
    // dispatcher; consulted post-create_jail when the operator's
    // uid is known via getpeereid (libnv socket path).
    Crated::setUmbrellaConfig(config.rctlUmbrella);

    // 1.1.12: register the per-user namespacing config for the privops
    // authorize-before-dispatch gate. Only zfsMasterPrefix is needed
    // (the gate checks the ZFS prefix and the uid-derived crate-<uid>
    // loginclass); network CIDRs are irrelevant to authorization and
    // left empty to avoid any CIDR parsing in composeForUid.
    // 1.1.15: also pass pathMasterPrefix so authorize() can gate
    // create_jail's brand-new path against env.pathPrefix.
    {
      PerUserEnvPure::Config authzCfg;
      authzCfg.zfsMasterPrefix  = config.zfsMasterPrefix;
      authzCfg.pathMasterPrefix = config.pathMasterPrefix;
      Crated::setPerUserAuthzConfig(authzCfg);
    }

    // 1.1.13: jid->owner registry for the jid- and name-scoped authz
    // gate. Loaded from /var/db/crate/jid_owners.tsv (created on first
    // create_jail). Jails that existed before this release are NOT in
    // the registry — the gate's bootstrap concession allows them
    // through to preserve the upgrade path. Any new jail created via
    // create_jail on the libnv path is recorded with its operator uid;
    // subsequent jid/name-scoped verbs from a different operator are
    // denied 403.
    static JidOwnerRegistry jidOwnerRegistry("/var/db/crate/jid_owners.tsv");
    Crated::setJidOwnerRegistry(&jidOwnerRegistry);

    Crated::PrivopsListener privopsListener(config);
    bool privopsStarted = privopsListener.start();

    std::cerr << "crated started";
    if (!config.unixSocket.empty())
      std::cerr << " unix=" << config.unixSocket;
    if (config.tcpPort != 0)
      std::cerr << " tcp=:" << config.tcpPort;
    if (wsStarted)
      std::cerr << " ws-console=[" << config.consoleWsBind
                << "]:" << config.consoleWsPort;
    if (csStarted > 0)
      std::cerr << " control-sockets=" << csStarted;
    if (privopsStarted)
      std::cerr << " privops=" << config.privopsSocketPath;
    std::cerr << std::endl;

    // Main loop — server runs in threads, we just wait for signals
    while (g_running)
      ::sleep(1);

    privopsListener.stop();
    controlSockets.stop();
    Crated::WsConsole::stop();
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
