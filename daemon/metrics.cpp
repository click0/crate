// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Prometheus metrics collector.
// Queries jls, rctl, and GUI registry to produce exposition format.

#include "metrics.h"

#include "gui_registry.h"
#include "pathnames.h"
#include "util.h"

#include <map>
#include <sstream>

namespace Crated {

// Parse rctl -u output ("resource=value\n" lines) into a key→value map.
// Extracted so it can be reused by `crate stats` (Phase 4) and other callers.
static std::map<std::string, std::string> parseRctlUsage(const std::string &rctlOutput) {
  std::map<std::string, std::string> result;
  std::istringstream is(rctlOutput);
  std::string line;
  while (std::getline(is, line)) {
    auto eqPos = line.find('=');
    if (eqPos == std::string::npos) continue;
    result[line.substr(0, eqPos)] = line.substr(eqPos + 1);
  }
  return result;
}

std::string collectPrometheusMetrics() {
  std::ostringstream ss;

  // --- Container count ---
  unsigned total = 0, running = 0;

  struct JailInfo {
    std::string jid;
    std::string name;
  };
  std::vector<JailInfo> jails;

  try {
    auto jlsOutput = Util::execCommandGetOutput(
      {CRATE_PATH_JLS, "-q", "jid", "name", "dying"}, "list jails");
    std::istringstream is(jlsOutput);
    std::string jid, name, dying;
    while (is >> jid >> name >> dying) {
      total++;
      if (dying == "0") {
        running++;
        jails.push_back({jid, name});
      }
    }
  } catch (...) {}

  ss << "# HELP crate_containers_total Total number of crate containers\n"
     << "# TYPE crate_containers_total gauge\n"
     << "crate_containers_total " << total << "\n"
     << "# HELP crate_containers_running Number of running containers\n"
     << "# TYPE crate_containers_running gauge\n"
     << "crate_containers_running " << running << "\n";

  // --- GUI sessions ---
  try {
    auto reg = Ctx::GuiRegistry::lock();
    auto entries = reg->getEntries();
    reg->unlock();

    ss << "# HELP crate_gui_sessions_total Active GUI sessions\n"
       << "# TYPE crate_gui_sessions_total gauge\n"
       << "crate_gui_sessions_total " << entries.size() << "\n";

    for (auto &e : entries) {
      auto labels = "jail=\"" + e.jailName + "\",mode=\"" + e.mode + "\"";
      ss << "crate_container_gui_display{" << labels << "} " << e.displayNum << "\n";
      if (e.vncPort)
        ss << "crate_container_gui_vnc_port{" << labels << "} " << e.vncPort << "\n";
      if (e.wsPort)
        ss << "crate_container_gui_ws_port{" << labels << "} " << e.wsPort << "\n";
    }
  } catch (...) {}

  // --- Per-container RCTL metrics ---
  if (!jails.empty()) {
    ss << "# HELP crate_container_cpu_percent CPU usage percentage\n"
       << "# TYPE crate_container_cpu_percent gauge\n"
       << "# HELP crate_container_memory_bytes Memory usage in bytes\n"
       << "# TYPE crate_container_memory_bytes gauge\n"
       << "# HELP crate_container_processes Number of processes\n"
       << "# TYPE crate_container_processes gauge\n"
       << "# HELP crate_container_openfiles Number of open files\n"
       << "# TYPE crate_container_openfiles gauge\n"
       << "# HELP crate_container_read_bps Disk read bytes per second\n"
       << "# TYPE crate_container_read_bps gauge\n"
       << "# HELP crate_container_write_bps Disk write bytes per second\n"
       << "# TYPE crate_container_write_bps gauge\n";

    for (auto &j : jails) {
      try {
        auto rctlOut = Util::execCommandGetOutput(
          {CRATE_PATH_RCTL, "-u", "jail:" + j.name}, "rctl usage");
        std::istringstream is(rctlOut);
        std::string line;
        auto label = "name=\"" + j.name + "\",jid=\"" + j.jid + "\"";
        while (std::getline(is, line)) {
          auto eq = line.find('=');
          if (eq == std::string::npos) continue;
          auto key = line.substr(0, eq);
          auto val = line.substr(eq + 1);
          if (key == "pcpu")
            ss << "crate_container_cpu_percent{" << label << "} " << val << "\n";
          else if (key == "memoryuse")
            ss << "crate_container_memory_bytes{" << label << "} " << val << "\n";
          else if (key == "maxproc")
            ss << "crate_container_processes{" << label << "} " << val << "\n";
          else if (key == "openfiles")
            ss << "crate_container_openfiles{" << label << "} " << val << "\n";
          else if (key == "readbps")
            ss << "crate_container_read_bps{" << label << "} " << val << "\n";
          else if (key == "writebps")
            ss << "crate_container_write_bps{" << label << "} " << val << "\n";
        }
      } catch (...) {}
    }
  }

  return ss.str();
}

}
