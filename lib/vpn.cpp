// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "commands.h"
#include "wireguard_pure.h"
#include "util.h"
#include "err.h"

#include <yaml-cpp/yaml.h>
#include <rang.hpp>

#include <iostream>
#include <vector>

#define ERR(msg...) ERR2("vpn", msg)

namespace {

std::vector<std::string> readScalarOrSeq(const YAML::Node &n) {
  std::vector<std::string> out;
  if (!n) return out;
  if (n.IsScalar()) { out.push_back(n.as<std::string>()); return out; }
  if (n.IsSequence()) for (auto e : n) out.push_back(e.as<std::string>());
  return out;
}

WireguardPure::InterfaceSpec parseInterface(const YAML::Node &n) {
  WireguardPure::InterfaceSpec i;
  if (n["private_key"])  i.privateKey = n["private_key"].as<std::string>();
  if (n["addresses"])    i.addresses  = readScalarOrSeq(n["addresses"]);
  if (n["address"])      i.addresses  = readScalarOrSeq(n["address"]);
  if (n["listen_port"]) {
    auto v = n["listen_port"];
    if (v.IsScalar()) i.listenPort = v.as<std::string>();
  }
  if (n["fwmark"])       i.fwmark    = n["fwmark"].as<std::string>();
  if (n["dns"])          i.dns       = readScalarOrSeq(n["dns"]);
  if (n["mtu"])          i.mtu.push_back(n["mtu"].as<std::string>());
  return i;
}

WireguardPure::PeerSpec parsePeer(const YAML::Node &n) {
  WireguardPure::PeerSpec p;
  if (n["public_key"])    p.publicKey    = n["public_key"].as<std::string>();
  if (n["preshared_key"]) p.presharedKey = n["preshared_key"].as<std::string>();
  if (n["allowed_ips"])   p.allowedIps   = readScalarOrSeq(n["allowed_ips"]);
  if (n["endpoint"])      p.endpoint     = n["endpoint"].as<std::string>();
  if (n["persistent_keepalive"]) {
    auto v = n["persistent_keepalive"];
    p.persistentKeepalive = v.IsScalar() ? v.as<std::string>() : "";
  }
  if (n["description"])   p.description  = n["description"].as<std::string>();
  return p;
}

} // anon

bool vpnCommand(const Args &args) {
  if (args.vpnSubcmd != "wireguard" || args.vpnAction != "render-conf")
    ERR("only 'vpn wireguard render-conf' is implemented")

  YAML::Node root;
  try {
    root = YAML::LoadFile(args.vpnSpecFile);
  } catch (const std::exception &e) {
    ERR("failed to load spec '" << args.vpnSpecFile << "': " << e.what())
  }

  if (!root["interface"]) ERR("spec must contain a top-level 'interface:' map")
  if (!root["peers"])     ERR("spec must contain a top-level 'peers:' list")

  auto iface = parseInterface(root["interface"]);
  std::vector<WireguardPure::PeerSpec> peers;
  for (auto p : root["peers"])
    peers.push_back(parsePeer(p));

  auto err = WireguardPure::validateConfig(iface, peers);
  if (!err.empty())
    ERR(err)

  std::cout << WireguardPure::renderConf(iface, peers);
  return true;
}
