// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// crate-hub — central aggregator for multi-host crate management.
// Polls crated instances on remote nodes, stores metrics in SQLite,
// serves aggregated REST API and Prometheus /metrics.
// Includes embedded web dashboard (hub/web/).

#include "poller.h"
#include "store.h"
#include "api.h"

#include <httplib.h>

#include <signal.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <thread>

static volatile sig_atomic_t g_running = 1;

static void signalHandler(int) { g_running = 0; }

int main(int argc, char **argv) {
  unsigned port = 9810;
  std::string configPath = "/usr/local/etc/crate-hub.conf";
  std::string webDir = "/usr/local/share/crate-hub/web";
  bool foreground = false;

  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "-f") foreground = true;
    else if (arg == "-c" && i + 1 < argc) configPath = argv[++i];
    else if (arg == "-p" && i + 1 < argc) port = std::stoi(argv[++i]);
    else if (arg == "-w" && i + 1 < argc) webDir = argv[++i];
    else if (arg == "-h") {
      std::cout << "Usage: crate-hub [-f] [-c config] [-p port] [-w webdir]\n";
      return 0;
    }
  }

  ::signal(SIGINT, signalHandler);
  ::signal(SIGTERM, signalHandler);

  // Load node configuration
  auto nodes = CrateHub::loadNodes(configPath);
  if (nodes.empty()) {
    std::cerr << "crate-hub: no nodes configured in " << configPath << std::endl;
    return 1;
  }

  // Optional HA specs (added in 0.7.3). Empty when no `ha:`
  // section present.
  long haThresholdSeconds = 60;
  auto haSpecs = CrateHub::loadHaSpecs(configPath, &haThresholdSeconds);
  if (auto reason = HaPure::validateSpecs(haSpecs); !reason.empty()) {
    std::cerr << "crate-hub: invalid HA spec: " << reason << std::endl;
    return 1;
  }

  // Initialize SQLite store
  CrateHub::Store store("/var/db/crate-hub/metrics.db");

  // Start poller thread
  CrateHub::Poller poller(nodes, store);
  std::thread pollerThread([&poller]() { poller.run(); });

  // Start HTTP server
  httplib::Server srv;
  CrateHub::registerApiRoutes(srv, store, poller, haSpecs, haThresholdSeconds);

  // Serve static web dashboard
  srv.set_mount_point("/", webDir);

  if (!foreground) {
    pid_t pid = ::fork();
    if (pid < 0) { std::cerr << "fork failed\n"; return 1; }
    if (pid > 0) ::_exit(0);
    ::setsid();
  }

  std::cerr << "crate-hub: listening on :" << port
            << ", " << nodes.size() << " nodes configured" << std::endl;

  std::thread srvThread([&srv, port]() {
    srv.listen("0.0.0.0", port);
  });

  while (g_running)
    ::sleep(1);

  srv.stop();
  poller.stop();
  srvThread.join();
  pollerThread.join();

  return 0;
}
