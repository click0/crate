// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Prometheus metrics collector.
// Queries jls, rctl, and GUI registry to produce exposition format.

#include "metrics.h"

#include "gui_registry.h"
#include "util.h"

#include <sstream>

namespace Crated {

std::string collectPrometheusMetrics() {
  std::ostringstream ss;

  // --- Container count ---
  unsigned total = 0, running = 0;
  try {
    auto jlsOutput = Util::execCommandGetOutput(
      {"/usr/sbin/jls", "-q", "jid", "name", "dying"}, "list jails");
    std::istringstream is(jlsOutput);
    std::string jid, name, dying;
    while (is >> jid >> name >> dying) {
      total++;
      if (dying == "0")
        running++;
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

  // --- Per-container RCTL metrics (if available) ---
  // TODO: iterate jails and query rctl for CPU/memory/network

  return ss.str();
}

}
