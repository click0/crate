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
      if (pollInterval == 0) {   // 1.1.50: 0 ran jls/rctl every 100 ms
        std::cerr << "crate-snmpd: -i must be at least 1 second" << std::endl;
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
  ::signal(SIGPIPE, SIG_IGN);   // 1.1.50: a write to a closed master must not kill us

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

  // Main loop:
  //   - Pump AgentX PDUs continuously (Get/GetNext) with a 100 ms select.
  //   - Re-collect metrics every `pollInterval` seconds.
  //   - Check for state-change traps after each collection.
  CrateSnmp::Collector collector;
  collector.collect();
  CrateSnmp::updateMibData(collector);
  time_t lastCollect = ::time(nullptr);
  // 1.1.50: reconnect with backoff when the master goes away (bsnmpd /
  // snmpd restart). 1 s, doubling to 30 s; re-register on success.
  unsigned backoffSec = 1;
  time_t nextReconnect = 0;
  while (g_running) {
    if (!CrateSnmp::agentxConnected()) {
      time_t now0 = ::time(nullptr);
      if (now0 >= nextReconnect) {
        if (CrateSnmp::initAgentX(agentxSocket)) {
          CrateSnmp::registerMib();
          std::cerr << "crate-snmpd: reconnected to AgentX master" << std::endl;
          backoffSec = 1;
        } else {
          nextReconnect = now0 + backoffSec;
          backoffSec = backoffSec >= 30 ? 30 : backoffSec * 2;
        }
      }
      ::usleep(100000);
    } else {
      CrateSnmp::dispatchOnce(100);     // 100 ms — cheap when idle
    }
    time_t now = ::time(nullptr);
    if ((unsigned)(now - lastCollect) >= pollInterval) {
      collector.collect();
      CrateSnmp::updateMibData(collector);
      collector.checkTraps();
      lastCollect = now;
    }
  }

  CrateSnmp::shutdownAgentX();
  return 0;
}
