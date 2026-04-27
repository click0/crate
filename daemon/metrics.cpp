// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Prometheus metrics collector.
// Queries jls, rctl, and GUI registry to produce exposition format.

#include "metrics.h"
#include "metrics_pure.h"

#include "gui_registry.h"
#include "pathnames.h"
#include "util.h"

#include <map>
#include <sstream>

namespace Crated {

// parseRctlUsage moved to daemon/metrics_pure.cpp
using MetricsPure::parseRctlUsage;

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
  // Query rctl -u for each running jail to get resource usage
  try {
    auto jlsOutput2 = Util::execCommandGetOutput(
      {"/usr/sbin/jls", "-q", "jid", "name"}, "list jails for rctl");
    std::istringstream jlsIs(jlsOutput2);
    std::string rjid, rname;

    bool headerWritten = false;
    while (jlsIs >> rjid >> rname) {
      try {
        auto rctlOutput = Util::execCommandGetOutput(
          {"/usr/bin/rctl", "-u", "jail:" + rjid}, "query RCTL usage");

        if (!headerWritten) {
          ss << "# HELP crate_container_memory_bytes Container memory usage in bytes\n"
             << "# TYPE crate_container_memory_bytes gauge\n"
             << "# HELP crate_container_cpu_pct Container CPU usage percent\n"
             << "# TYPE crate_container_cpu_pct gauge\n"
             << "# HELP crate_container_maxproc Container max processes\n"
             << "# TYPE crate_container_maxproc gauge\n"
             << "# HELP crate_container_openfiles Container open file descriptors\n"
             << "# TYPE crate_container_openfiles gauge\n"
             << "# HELP crate_container_readbps Container read bytes per second\n"
             << "# TYPE crate_container_readbps gauge\n"
             << "# HELP crate_container_writebps Container write bytes per second\n"
             << "# TYPE crate_container_writebps gauge\n";
          headerWritten = true;
        }

        auto rctlMap = parseRctlUsage(rctlOutput);
        auto labels = "name=\"" + rname + "\"";

        auto emit = [&](const char *rctlKey, const char *metricName) {
          auto it = rctlMap.find(rctlKey);
          if (it != rctlMap.end())
            ss << metricName << "{" << labels << "} " << it->second << "\n";
        };

        emit("memoryuse",  "crate_container_memory_bytes");
        emit("pcpu",       "crate_container_cpu_pct");
        emit("maxproc",    "crate_container_maxproc");
        emit("openfiles",  "crate_container_openfiles");
        emit("readbps",    "crate_container_readbps");
        emit("writebps",   "crate_container_writebps");
      } catch (...) {
        // RCTL might not be available for this jail
      }
    }
  } catch (...) {}

  return ss.str();
}

}
