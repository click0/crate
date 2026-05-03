// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "api.h"
#include "aggregator_pure.h"
#include "datacenter_pure.h"
#include "ha_pure.h"
#include "poller.h"
#include "store.h"

#include <httplib.h>

#include <ctime>
#include <sstream>

namespace CrateHub {

void registerApiRoutes(httplib::Server &srv, Store &store, Poller &poller,
                       const std::vector<HaPure::HaSpec> &haSpecs,
                       long haThresholdSeconds) {
  // Health check
  srv.Get("/healthz", [](const httplib::Request &, httplib::Response &res) {
    res.set_content("{\"status\":\"ok\"}", "application/json");
  });

  // GET /api/v1/nodes — list all nodes with status
  srv.Get("/api/v1/nodes", [&poller](const httplib::Request &, httplib::Response &res) {
    auto statuses = poller.getNodeStatuses();
    std::ostringstream ss;
    ss << "[";
    for (size_t i = 0; i < statuses.size(); i++) {
      auto &s = statuses[i];
      ss << "{\"name\":\"" << s.name << "\""
         << ",\"host\":\"" << s.host << "\""
         << ",\"reachable\":" << (s.reachable ? "true" : "false");
      if (!s.lastError.empty())
        ss << ",\"error\":\"" << s.lastError << "\"";
      ss << "}";
      if (i + 1 < statuses.size()) ss << ",";
    }
    ss << "]";
    res.set_content("{\"status\":\"ok\",\"data\":" + ss.str() + "}", "application/json");
  });

  // GET /api/v1/nodes/:host/containers — containers on specific node
  srv.Get("/api/v1/nodes/:host/containers",
    [&poller](const httplib::Request &req, httplib::Response &res) {
      auto host = req.path_params.at("host");
      auto statuses = poller.getNodeStatuses();
      for (auto &s : statuses) {
        if (s.name == host || s.host == host) {
          if (s.containers.empty())
            res.set_content("{\"status\":\"ok\",\"data\":[]}", "application/json");
          else
            res.set_content("{\"status\":\"ok\",\"data\":" + s.containers + "}", "application/json");
          return;
        }
      }
      res.status = 404;
      res.set_content("{\"status\":\"error\",\"error\":\"node not found\"}", "application/json");
    });

  // GET /api/v1/containers — all containers across all nodes
  srv.Get("/api/v1/containers", [&poller](const httplib::Request &, httplib::Response &res) {
    auto statuses = poller.getNodeStatuses();
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (auto &s : statuses) {
      if (!s.containers.empty()) {
        // Inject node name into container data
        // For now, return raw arrays wrapped with node info
        if (!first) ss << ",";
        ss << "{\"node\":\"" << s.name << "\",\"containers\":" << s.containers << "}";
        first = false;
      }
    }
    ss << "]";
    res.set_content("{\"status\":\"ok\",\"data\":" + ss.str() + "}", "application/json");
  });

  // GET /metrics — Prometheus format (aggregated from all nodes)
  srv.Get("/metrics", [&poller](const httplib::Request &, httplib::Response &res) {
    auto statuses = poller.getNodeStatuses();
    std::ostringstream ss;
    ss << "# HELP crate_hub_nodes_total Total configured nodes\n"
       << "# TYPE crate_hub_nodes_total gauge\n"
       << "crate_hub_nodes_total " << statuses.size() << "\n";

    unsigned reachable = 0;
    for (auto &s : statuses)
      if (s.reachable) reachable++;
    ss << "# HELP crate_hub_nodes_reachable Reachable nodes\n"
       << "# TYPE crate_hub_nodes_reachable gauge\n"
       << "crate_hub_nodes_reachable " << reachable << "\n";

    for (auto &s : statuses) {
      ss << "crate_hub_node_up{host=\"" << s.name << "\"} "
         << (s.reachable ? 1 : 0) << "\n";
    }

    res.set_content(ss.str(), "text/plain; version=0.0.4");
  });

  // GET /api/v1/aggregate — single-shot summary for the web dashboard.
  // Reuses the pure aggregator + countTopLevelObjects helpers.
  srv.Get("/api/v1/aggregate", [&poller](const httplib::Request &, httplib::Response &res) {
    auto statuses = poller.getNodeStatuses();
    std::vector<AggregatorPure::NodeView> views;
    views.reserve(statuses.size());
    for (auto &s : statuses) {
      AggregatorPure::NodeView v;
      v.name = s.name;
      v.host = s.host;
      v.reachable = s.reachable;
      v.containerCount = AggregatorPure::countTopLevelObjects(s.containers);
      views.push_back(std::move(v));
    }
    auto sum = AggregatorPure::summarise(views);
    auto json = AggregatorPure::renderSummaryJson(sum);
    res.set_content("{\"status\":\"ok\",\"data\":" + json + "}", "application/json");
  });

  // GET /api/v1/datacenters — per-DC summary (nodes total/reachable/down,
  // containers total). Reuses the pure aggregator for container counts.
  srv.Get("/api/v1/datacenters", [&poller](const httplib::Request &, httplib::Response &res) {
    auto statuses = poller.getNodeStatuses();
    std::vector<DatacenterPure::DcView> views;
    views.reserve(statuses.size());
    for (auto &s : statuses) {
      DatacenterPure::DcView v;
      v.node.name = s.name;
      v.node.host = s.host;
      v.node.reachable = s.reachable;
      v.node.containerCount = AggregatorPure::countTopLevelObjects(s.containers);
      v.datacenter = s.datacenter;
      views.push_back(std::move(v));
    }
    auto summaries = DatacenterPure::groupAndSummarise(views);
    auto json = DatacenterPure::renderJson(summaries);
    res.set_content("{\"status\":\"ok\",\"data\":" + json + "}", "application/json");
  });

  // GET /api/v1/ha/orders — HA failover decisions for an external
  // consumer (cron + `crate migrate`, or a future `crate ha-execute`).
  // The hub does NOT execute migrations itself — it would need
  // admin tokens for the per-node daemons, which violates the
  // 0.6.7 architecture (tokens stay in operator localStorage / a
  // chmod-600 file). The body is a list, possibly empty when no
  // failovers are needed right now. Deterministic — calling this
  // while node state is unchanged returns the same orders, so
  // consumers won't see flapping.
  srv.Get("/api/v1/ha/orders",
          [&poller, &haSpecs, haThresholdSeconds]
          (const httplib::Request &, httplib::Response &res) {
    auto statuses = poller.getNodeStatuses();
    long now = (long)::time(nullptr);
    std::vector<HaPure::NodeView> views;
    views.reserve(statuses.size());
    for (auto &s : statuses) {
      HaPure::NodeView v;
      v.name = s.name;
      v.reachable = s.reachable;
      v.unreachableSeconds =
        (s.firstDownAt > 0 && !s.reachable) ? (now - (long)s.firstDownAt) : 0;
      views.push_back(std::move(v));
    }
    auto orders = HaPure::evaluateFailoverOrders(haSpecs, views,
                                                 haThresholdSeconds);
    auto json = HaPure::renderOrdersJson(orders);
    res.set_content("{\"status\":\"ok\",\"data\":" + json + "}",
                    "application/json");
  });

  // Prune old data periodically (called by main loop or as endpoint)
  srv.Post("/api/v1/admin/prune", [&store](const httplib::Request &, httplib::Response &res) {
    store.prune(48);
    res.set_content("{\"status\":\"ok\"}", "application/json");
  });
}

}
