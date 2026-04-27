// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Container lifecycle commands: stats, logs, stop, restart.

#include "args.h"
#include "commands.h"
#include "jail_query.h"
#include "lifecycle_pure.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <chrono>

#define ERR(msg...) ERR2("lifecycle", msg)

// --- helpers ---

// Parse an unsigned 64-bit number from rctl output. rctl output is controlled
// by the kernel and should always be numeric, but guard against malformed
// fields (truncated pipes, locale-specific output, etc.) instead of leaking a
// std::invalid_argument / std::out_of_range from std::stoull to the caller.
static unsigned long long safeStoull(const std::string &s) {
  try {
    return std::stoull(s);
  } catch (const std::exception &) {
    return 0ULL;
  }
}

// --- crate stats TARGET ---

// humanBytes moved to lib/lifecycle_pure.cpp
using LifecyclePure::humanBytes;

bool statsCrate(const Args &args) {
  // Resolve target to JID
  auto jail = JailQuery::getJailByName(args.statsTarget);
  if (!jail) {
    // Try as JID
    try {
      int jid = std::stoi(args.statsTarget);
      jail = JailQuery::getJailByJid(jid);
    } catch (...) {}
  }
  if (!jail) {
    std::cerr << rang::fg::red << "container '" << args.statsTarget
              << "' not found" << rang::style::reset << std::endl;
    return false;
  }

  auto jidStr = std::to_string(jail->jid);

  // Query RCTL usage
  std::string rctlOutput;
  try {
    rctlOutput = Util::execCommandGetOutput(
      {CRATE_PATH_RCTL, "-u", STR("jail:" << jidStr)}, "query RCTL usage");
  } catch (...) {
    std::cerr << rang::fg::yellow << "warning: RCTL not available (kern.racct.enable=1?)"
              << rang::style::reset << std::endl;
  }

  // Parse RCTL output into key-value pairs
  std::map<std::string, std::string> usage;
  {
    std::istringstream is(rctlOutput);
    std::string line;
    while (std::getline(is, line)) {
      auto eq = line.find('=');
      if (eq != std::string::npos)
        usage[line.substr(0, eq)] = line.substr(eq + 1);
    }
  }

  // Query RCTL limits
  std::map<std::string, std::string> limits;
  try {
    auto limOutput = Util::execCommandGetOutput(
      {CRATE_PATH_RCTL, "-l", STR("jail:" << jidStr)}, "query RCTL limits");
    std::istringstream is(limOutput);
    std::string line;
    while (std::getline(is, line)) {
      // Format: jail:JID:resource:action=value
      auto lastColon = line.rfind(':');
      if (lastColon == std::string::npos) continue;
      auto eqPos = line.find('=', lastColon);
      if (eqPos == std::string::npos) continue;
      // Extract resource name: between 2nd and 3rd colon
      auto c1 = line.find(':');
      auto c2 = line.find(':', c1 + 1);
      auto c3 = line.find(':', c2 + 1);
      if (c2 != std::string::npos && c3 != std::string::npos) {
        auto resource = line.substr(c2 + 1, c3 - c2 - 1);
        auto value = line.substr(eqPos + 1);
        limits[resource] = value;
      }
    }
  } catch (...) {}

  // Query network I/O via netstat on the jail's epair interface
  std::string netIn = "-", netOut = "-";
  try {
    // Find the epair interface inside the jail (e.g., "epair0b")
    auto ifOutput = JailExec::execInJailGetOutput(
      jail->jid, {CRATE_PATH_IFCONFIG, "-l"}, "root", "list jail interfaces");
    // Parse interface list to find the epair interface
    std::string epairIface;
    {
      std::istringstream ifs(ifOutput);
      std::string iface;
      while (ifs >> iface) {
        if (iface.substr(0, 5) == "epair") {
          epairIface = iface;
          break;
        }
      }
    }
    if (!epairIface.empty()) {
      // Derive host-side interface: epairNb -> epairNa
      std::string hostIface = epairIface;
      if (hostIface.back() == 'b')
        hostIface.back() = 'a';
      // Run netstat -I <iface> -b on the host to get byte counts
      auto nsOutput = Util::execCommandGetOutput(
        {CRATE_PATH_NETSTAT, "-I", hostIface, "-b", "-n", "--libxo", "json"},
        "query netstat interface stats");
      // Fallback: parse tabular netstat output if JSON not available
      if (nsOutput.empty() || nsOutput[0] != '{') {
        // Try without --libxo
        nsOutput = Util::execCommandGetOutput(
          {CRATE_PATH_NETSTAT, "-I", hostIface, "-b", "-n"},
          "query netstat interface stats");
        // Parse tabular output: header line then data line
        // Format: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
        std::istringstream nss(nsOutput);
        std::string nsLine;
        bool headerSeen = false;
        while (std::getline(nss, nsLine)) {
          if (nsLine.find("Ibytes") != std::string::npos) {
            headerSeen = true;
            continue;
          }
          if (headerSeen && !nsLine.empty()) {
            std::istringstream ls(nsLine);
            std::string name, mtu, network, address;
            uint64_t ipkts, ierrs, ibytes, opkts, oerrs, obytes;
            if (ls >> name >> mtu >> network >> address >> ipkts >> ierrs >> ibytes >> opkts >> oerrs >> obytes) {
              netIn = humanBytes(ibytes);
              netOut = humanBytes(obytes);
            }
            break;
          }
        }
      }
    }
  } catch (...) {
    // Network I/O not available, keep "-"
  }

  if (args.statsJson) {
    // JSON output
    std::cout << "{\"name\":\"" << jail->name << "\""
              << ",\"jid\":" << jail->jid
              << ",\"ip\":\"" << jail->ip4 << "\"";
    for (auto &kv : usage)
      std::cout << ",\"" << kv.first << "\":" << kv.second;
    if (netIn != "-")
      std::cout << ",\"net_in\":\"" << netIn << "\"";
    if (netOut != "-")
      std::cout << ",\"net_out\":\"" << netOut << "\"";
    std::cout << "}" << std::endl;
    return true;
  }

  // Table output
  auto memUsed = usage.count("memoryuse") ? safeStoull(usage["memoryuse"]) : 0ULL;
  auto memLimit = limits.count("memoryuse") ? limits["memoryuse"] : "-";
  auto cpuPct = usage.count("pcpu") ? usage["pcpu"] : "0";
  auto procs = usage.count("maxproc") ? usage["maxproc"] : "0";
  auto procLimit = limits.count("maxproc") ? limits["maxproc"] : "-";

  std::cout << std::left;
  std::cout << std::setw(14) << "NAME"
            << std::setw(8) << "CPU%"
            << std::setw(12) << "MEM"
            << std::setw(10) << "MEM LIM"
            << std::setw(10) << "PIDS"
            << std::setw(10) << "PID LIM"
            << std::setw(10) << "NET_IN"
            << std::setw(10) << "NET_OUT"
            << std::setw(16) << "IP"
            << std::endl;
  std::cout << std::string(98, '-') << std::endl;
  std::cout << std::setw(14) << jail->name
            << std::setw(8) << (cpuPct + "%")
            << std::setw(12) << humanBytes(memUsed)
            << std::setw(10) << memLimit
            << std::setw(10) << procs
            << std::setw(10) << procLimit
            << std::setw(10) << netIn
            << std::setw(10) << netOut
            << std::setw(16) << (jail->ip4.empty() ? "-" : jail->ip4)
            << std::endl;

  // Additional I/O stats if available
  if (usage.count("readbps") || usage.count("writebps")) {
    std::cout << std::endl << "I/O:" << std::endl;
    if (usage.count("readbps"))
      std::cout << "  Read:  " << humanBytes(safeStoull(usage["readbps"])) << "/s" << std::endl;
    if (usage.count("writebps"))
      std::cout << "  Write: " << humanBytes(safeStoull(usage["writebps"])) << "/s" << std::endl;
  }

  return true;
}

// --- crate logs TARGET ---

bool logsCrate(const Args &args) {
  // Look for container logs in /var/log/crate/<name>/
  auto logDir = STR("/var/log/crate/" << args.logsTarget);
  auto stdoutLog = logDir + "/stdout.log";
  auto stderrLog = logDir + "/stderr.log";

  // Also check if the jail is running and try console.log
  auto consoleLog = logDir + "/console.log";

  std::string logFile;
  if (Util::Fs::fileExists(consoleLog))
    logFile = consoleLog;
  else if (Util::Fs::fileExists(stdoutLog))
    logFile = stdoutLog;
  else {
    // Try to read from the jail path
    auto jail = JailQuery::getJailByName(args.logsTarget);
    if (jail && !jail->path.empty()) {
      auto jailLog = jail->path + "/var/log/messages";
      if (Util::Fs::fileExists(jailLog))
        logFile = jailLog;
    }
  }

  if (logFile.empty()) {
    std::cerr << rang::fg::red << "no logs found for '" << args.logsTarget
              << "' (checked " << logDir << "/)" << rang::style::reset << std::endl;
    return false;
  }

  if (args.logsFollow) {
    // Follow mode: tail -f equivalent
    std::ifstream ifs(logFile);
    if (!ifs.good()) {
      std::cerr << rang::fg::red << "cannot open " << logFile << rang::style::reset << std::endl;
      return false;
    }

    // Seek to end, then poll for new data
    ifs.seekg(0, std::ios::end);
    std::string line;
    while (true) {
      while (std::getline(ifs, line))
        std::cout << line << std::endl;
      ifs.clear();
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
  } else {
    // Read entire file or last N lines
    std::ifstream ifs(logFile);
    if (!ifs.good()) {
      std::cerr << rang::fg::red << "cannot open " << logFile << rang::style::reset << std::endl;
      return false;
    }

    if (args.logsTail > 0) {
      // Read last N lines using a circular buffer
      std::deque<std::string> lines;
      std::string line;
      while (std::getline(ifs, line)) {
        lines.push_back(line);
        if (lines.size() > args.logsTail)
          lines.pop_front();
      }
      for (auto &l : lines)
        std::cout << l << std::endl;
    } else {
      // Print all
      std::string line;
      while (std::getline(ifs, line))
        std::cout << line << std::endl;
    }
  }

  return true;
}

// --- crate stop TARGET ---

bool stopCrate(const Args &args) {
  // Find the running jail
  auto jail = JailQuery::getJailByName(args.stopTarget);
  if (!jail) {
    try {
      int jid = std::stoi(args.stopTarget);
      jail = JailQuery::getJailByJid(jid);
    } catch (...) {}
  }
  if (!jail) {
    std::cerr << rang::fg::red << "container '" << args.stopTarget
              << "' not found or not running" << rang::style::reset << std::endl;
    return false;
  }

  std::cout << "Stopping container " << jail->name << " (jid=" << jail->jid << ")..." << std::endl;

  // Send SIGTERM to all processes in the jail
  // Use jexec to kill the main process group
  try {
    Util::execCommand({CRATE_PATH_JEXEC, std::to_string(jail->jid),
                       "/bin/kill", "-TERM", "-1"},
      "send SIGTERM to jail processes");
  } catch (...) {
    // Jail might have no processes
  }

  // Wait for jail to exit
  for (unsigned i = 0; i < args.stopTimeout; i++) {
    auto check = JailQuery::getJailByJid(jail->jid);
    if (!check) {
      std::cout << rang::fg::green << "Container " << jail->name
                << " stopped." << rang::style::reset << std::endl;
      return true;
    }
    ::sleep(1);
  }

  // Force kill with SIGKILL
  std::cout << "Timeout reached, sending SIGKILL..." << std::endl;
  try {
    Util::execCommand({CRATE_PATH_JEXEC, std::to_string(jail->jid),
                       "/bin/kill", "-KILL", "-1"},
      "send SIGKILL to jail processes");
  } catch (...) {}

  // Wait briefly for cleanup
  ::sleep(1);

  // Remove the jail if it's still around
  auto stillRunning = JailQuery::getJailByJid(jail->jid);
  if (stillRunning) {
    try {
      // Force remove jail
      Util::execCommand({CRATE_PATH_JAIL, "-r", std::to_string(jail->jid)},
        "force remove jail");
    } catch (...) {}
  }

  std::cout << rang::fg::green << "Container " << jail->name
            << " stopped." << rang::style::reset << std::endl;
  return true;
}

// --- crate restart TARGET ---

bool restartCrate(const Args &args) {
  // Find the running container's crate file before stopping
  auto jail = JailQuery::getJailByName(args.restartTarget);
  if (!jail) {
    try {
      int jid = std::stoi(args.restartTarget);
      jail = JailQuery::getJailByJid(jid);
    } catch (...) {}
  }
  if (!jail) {
    std::cerr << rang::fg::red << "container '" << args.restartTarget
              << "' not found or not running" << rang::style::reset << std::endl;
    return false;
  }

  // Remember the jail path for restart
  auto jailPath = jail->path;
  auto jailName = jail->name;

  // Stop the container
  Args stopArgs;
  stopArgs.stopTarget = args.restartTarget;
  stopArgs.stopTimeout = args.restartTimeout;
  if (!stopCrate(stopArgs))
    return false;

  // Look for .crate file to restart from
  // Convention: crate file is stored at /var/run/crate/<name>.crate
  auto crateFile = STR("/var/run/crate/" << jailName << ".crate");
  if (!Util::Fs::fileExists(crateFile)) {
    // Try with path-based name
    auto bareName = Util::filePathToBareName(jailPath);
    crateFile = STR("/var/run/crate/" << bareName << ".crate");
  }

  if (!Util::Fs::fileExists(crateFile)) {
    std::cerr << rang::fg::yellow << "Container stopped but cannot restart: "
              << "no .crate file found for '" << jailName << "'"
              << rang::style::reset << std::endl;
    std::cerr << "To restart, run: crate run -f <crate-file>" << std::endl;
    return false;
  }

  std::cout << "Restarting container " << jailName << "..." << std::endl;

  // Run the container again
  Args runArgs;
  runArgs.cmd = CmdRun;
  runArgs.runCrateFile = crateFile;
  runArgs.logProgress = args.logProgress;

  int returnCode = 0;
  return runCrate(runArgs, 0, nullptr, returnCode);
}
