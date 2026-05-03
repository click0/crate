// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "poller.h"

#include <httplib.h>
#include <yaml-cpp/yaml.h>

#include <chrono>
#include <iostream>
#include <thread>

namespace CrateHub {

std::vector<NodeConfig> loadNodes(const std::string &configPath) {
  std::vector<NodeConfig> nodes;
  try {
    YAML::Node root = YAML::LoadFile(configPath);
    if (auto nodeList = root["nodes"]) {
      for (auto n : nodeList) {
        NodeConfig nc;
        nc.name = n["name"].as<std::string>(n["host"].as<std::string>());
        nc.host = n["host"].as<std::string>();
        nc.tlsCert = n["tls_cert"].as<std::string>("");
        nc.tlsKey = n["tls_key"].as<std::string>("");
        nc.token = n["token"].as<std::string>("");
        nc.datacenter = n["datacenter"].as<std::string>("");
        nodes.push_back(nc);
      }
    }
    if (root["poll_interval"])
      ; // TODO: parse into pollIntervalSec_
  } catch (const std::exception &e) {
    std::cerr << "crate-hub: failed to load config: " << e.what() << std::endl;
  }
  return nodes;
}

Poller::Poller(const std::vector<NodeConfig> &nodes, Store &store)
  : nodes_(nodes), store_(store)
{
  statuses_.resize(nodes.size());
  for (size_t i = 0; i < nodes.size(); i++) {
    statuses_[i].name = nodes[i].name;
    statuses_[i].host = nodes[i].host;
    statuses_[i].datacenter = nodes[i].datacenter;
  }
}

void Poller::run() {
  while (running_) {
    for (size_t i = 0; i < nodes_.size(); i++) {
      if (!running_) break;
      pollNode(nodes_[i], statuses_[i]);
    }
    // Wait for next poll cycle
    for (unsigned s = 0; s < pollIntervalSec_ && running_; s++)
      std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

void Poller::stop() {
  running_ = false;
}

void Poller::pollNode(const NodeConfig &node, NodeStatus &status) {
  try {
    // Parse host:port
    auto colon = node.host.rfind(':');
    auto host = node.host.substr(0, colon);
    int port = (colon != std::string::npos) ? std::stoi(node.host.substr(colon + 1)) : 9800;

    // Create HTTP client (TLS if cert provided)
    std::unique_ptr<httplib::Client> cli;
    if (!node.tlsCert.empty()) {
      cli = std::make_unique<httplib::SSLClient>(host, port,
        node.tlsCert, node.tlsKey);
    } else {
      cli = std::make_unique<httplib::Client>(host, port);
    }
    cli->set_connection_timeout(5, 0);
    cli->set_read_timeout(10, 0);

    if (!node.token.empty())
      cli->set_bearer_token_auth(node.token);

    // Fetch /api/v1/host
    auto hostRes = cli->Get("/api/v1/host");
    if (hostRes && hostRes->status == 200) {
      std::lock_guard<std::mutex> lock(statusMutex_);
      status.hostInfo = hostRes->body;
      status.reachable = true;
    }

    // Fetch /api/v1/containers
    auto ctRes = cli->Get("/api/v1/containers");
    if (ctRes && ctRes->status == 200) {
      std::lock_guard<std::mutex> lock(statusMutex_);
      status.containers = ctRes->body;
    }

    status.lastError.clear();

    // Store metrics in SQLite
    store_.recordPoll(node.name, status.hostInfo, status.containers);

  } catch (const std::exception &e) {
    std::lock_guard<std::mutex> lock(statusMutex_);
    status.reachable = false;
    status.lastError = e.what();
  }
}

std::vector<Poller::NodeStatus> Poller::getNodeStatuses() const {
  std::lock_guard<std::mutex> lock(statusMutex_);
  return statuses_;
}

}
