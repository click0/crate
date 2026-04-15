// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// crate-snmpd — SNMP AgentX subagent for crate container monitoring.
// Connects to bsnmpd (FreeBSD native) or net-snmp snmpd.
// Exposes CRATE-MIB: container table, GUI sessions, traps.

#include "collector.h"
#include "mib.h"

#include "util.h"

#include <signal.h>
#include <unistd.h>

#include <iostream>

static volatile sig_atomic_t g_running = 1;

static void signalHandler(int) {
  g_running = 0;
}

static void usage() {
  std::cerr << "Usage: crate-snmpd [-f] [-p agentx-socket] [-i interval]\n"
            << "  -f             Run in foreground\n"
            << "  -p socket      AgentX socket (default: /var/agentx/master)\n"
            << "  -i seconds     Polling interval (default: 30)\n";
}

int main(int argc, char **argv) {
  bool foreground = false;
  std::string agentxSocket = "/var/agentx/master";
  unsigned pollInterval = 30;

  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "-f")
      foreground = true;
    else if (arg == "-p" && i + 1 < argc)
      agentxSocket = argv[++i];
    else if (arg == "-i" && i + 1 < argc) {
      try {
        pollInterval = Util::toUInt(argv[++i]);
      } catch (const std::exception &e) {
        std::cerr << "crate-snmpd: invalid value for -i: " << e.what() << std::endl;
        return 1;
      }
    }
    else if (arg == "-h") {
      usage();
      return 0;
    }
  }

  ::signal(SIGINT, signalHandler);
  ::signal(SIGTERM, signalHandler);

  // Initialize AgentX connection
  if (!CrateSnmp::initAgentX(agentxSocket)) {
    std::cerr << "crate-snmpd: failed to connect to AgentX at " << agentxSocket << std::endl;
    return 1;
  }

  // Register CRATE-MIB OIDs
  CrateSnmp::registerMib();

  if (!foreground) {
    pid_t pid = ::fork();
    if (pid < 0) { std::cerr << "fork failed\n"; return 1; }
    if (pid > 0) ::_exit(0);
    ::setsid();
  }

  std::cerr << "crate-snmpd: started, polling every " << pollInterval << "s" << std::endl;

  // Main loop: collect metrics periodically
  CrateSnmp::Collector collector;
  while (g_running) {
    collector.collect();
    CrateSnmp::updateMibData(collector);

    // Check for state changes → send traps
    collector.checkTraps();

    for (unsigned i = 0; i < pollInterval && g_running; i++)
      ::sleep(1);
  }

  CrateSnmp::shutdownAgentX();
  return 0;
}
