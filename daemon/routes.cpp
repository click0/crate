// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// REST API routes — F1 minimal: read-only endpoints.

#include "routes.h"
#include "auth.h"
#include "metrics.h"

#include <httplib.h>

#include "args.h"
#include "commands.h"
#include "gui_registry.h"
#include "locs.h"
#include "util.h"

#include <sstream>

namespace Crated {

// --- JSON helpers ---

static void jsonOk(httplib::Response &res, const std::string &data) {
  res.set_content("{\"status\":\"ok\",\"data\":" + data + "}", "application/json");
}

static void jsonError(httplib::Response &res, int code, const std::string &msg) {
  res.status = code;
  res.set_content("{\"status\":\"error\",\"error\":\"" + msg + "\"}", "application/json");
}

// --- GET /api/v1/containers ---
// Returns JSON array of running containers (delegates to jls).

static void handleListContainers(const httplib::Request &, httplib::Response &res) {
  try {
    // Use Util::execCommandGetOutput to call jls and parse
    auto jlsOutput = Util::execCommandGetOutput(
      {"/usr/sbin/jls", "--libxo", "json"}, "list jails");
    // jls --libxo json returns valid JSON directly
    jsonOk(res, jlsOutput);
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- GET /api/v1/containers/{name}/gui ---

static void handleContainerGui(const httplib::Request &req, httplib::Response &res) {
  auto name = req.path_params.at("name");
  try {
    auto reg = Ctx::GuiRegistry::lock();
    auto *entry = reg->findByTarget(name);
    if (!entry) {
      reg->unlock();
      jsonError(res, 404, "no GUI session for container '" + name + "'");
      return;
    }
    auto e = *entry;
    reg->unlock();

    std::ostringstream ss;
    ss << "{\"display\":" << e.displayNum
       << ",\"pid\":" << e.ownerPid
       << ",\"xpid\":" << e.xServerPid
       << ",\"vnc_port\":" << e.vncPort
       << ",\"ws_port\":" << e.wsPort
       << ",\"mode\":\"" << e.mode << "\""
       << ",\"jail\":\"" << e.jailName << "\""
       << "}";
    jsonOk(res, ss.str());
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- GET /api/v1/host ---

static void handleHostInfo(const httplib::Response &, httplib::Response &res) {
  try {
    auto osrelease = Util::getSysctlString("kern.osrelease");
    auto hostname = Util::getSysctlString("kern.hostname");
    auto machine = Util::getSysctlString("hw.machine");
    auto ncpu = Util::getSysctlInt("hw.ncpu");
    auto physmem = Util::getSysctlInt("hw.physmem");

    std::ostringstream ss;
    ss << "{\"hostname\":\"" << hostname << "\""
       << ",\"osrelease\":\"" << osrelease << "\""
       << ",\"machine\":\"" << machine << "\""
       << ",\"ncpu\":" << ncpu
       << ",\"physmem\":" << physmem
       << "}";
    jsonOk(res, ss.str());
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- GET /metrics ---

static void handleMetrics(const httplib::Request &, httplib::Response &res) {
  res.set_content(Crated::collectPrometheusMetrics(), "text/plain; version=0.0.4");
}

// --- Route registration ---

void registerRoutes(httplib::Server &srv, const Config &config) {
  // Health check
  srv.Get("/healthz", [](const httplib::Request &, httplib::Response &res) {
    res.set_content("{\"status\":\"ok\"}", "application/json");
  });

  // API v1 — read-only (F1)
  srv.Get("/api/v1/containers", handleListContainers);
  srv.Get("/api/v1/containers/:name/gui", handleContainerGui);
  srv.Get("/api/v1/host", [](const httplib::Request &req, httplib::Response &res) {
    handleHostInfo(res, res);
  });

  // Prometheus metrics (no auth)
  srv.Get("/metrics", handleMetrics);

  // TODO F2: POST /api/v1/containers (create)
  // TODO F2: DELETE /api/v1/containers/:name (destroy)
  // TODO F2: POST /api/v1/containers/:name/start
  // TODO F2: POST /api/v1/containers/:name/stop
  // TODO F2: GET /api/v1/containers/:name/console (WebSocket)
  // TODO F2: GET /api/v1/containers/:name/stats
  // TODO F2: snapshots, export, import
}

}
