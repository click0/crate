// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "spec.h"
#include "locs.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define ERR(msg...) \
  ERR2("list", msg)

struct CrateEntry {
  int jid;
  std::string name;       // jail name (basename of jailPath)
  std::string path;       // jail root path
  std::string ip;         // primary IP (from epair)
  std::string hostname;
  std::string specFile;   // +CRATE.SPEC path if present
  std::string ports;      // inbound ports summary (from spec)
  std::string mounts;     // shared dirs count (from spec)
  bool hasHealthcheck = false; // healthcheck defined in spec
};

// Parse jls output to find running crate jails.
// crate jails live under /var/run/crate/jail-*
static std::vector<CrateEntry> discoverRunningCrates() {
  std::vector<CrateEntry> entries;
  std::string output;
  try {
    output = Util::execCommandGetOutput(
      {CRATE_PATH_JLS, "-N", "-h",
       "--libxo:J"},
      "list jails (JSON)");
  } catch (...) {
    // jls may fail if no jails exist — that's fine
    return entries;
  }

  // Fallback: parse plain jls output (JID  IP  Hostname  Path)
  // Use -N for column headers
  std::string plainOutput;
  try {
    plainOutput = Util::execCommandGetOutput(
      {CRATE_PATH_JLS, "-N"},
      "list jails");
  } catch (...) {
    return entries;
  }

  std::istringstream is(plainOutput);
  std::string line;
  bool header = true;
  auto cratePrefix = std::string(Locations::jailDirectoryPath) + "/jail-";
  while (std::getline(is, line)) {
    if (header) { header = false; continue; }
    if (line.empty()) continue;
    // jls -N columns: JID  IP Address  Hostname  Path
    std::istringstream ls(line);
    CrateEntry e;
    std::string ipStr;
    ls >> e.jid >> ipStr >> e.hostname >> e.path;
    if (e.path.find(cratePrefix) != 0)
      continue;  // not a crate jail
    e.ip = (ipStr == "-") ? "" : ipStr;
    e.name = e.path.substr(std::string(Locations::jailDirectoryPath).size() + 1);
    // check for +CRATE.SPEC and extract info
    auto specPath = e.path + "/+CRATE.SPEC";
    if (Util::Fs::fileExists(specPath)) {
      e.specFile = specPath;
      try {
        auto spec = parseSpec(specPath);
        // Ports: summarize inbound TCP/UDP
        if (auto optNet = spec.optionNet()) {
          std::ostringstream ps;
          for (size_t pi = 0; pi < optNet->inboundPortsTcp.size(); pi++) {
            if (pi > 0) ps << ",";
            auto &pr = optNet->inboundPortsTcp[pi];
            if (pr.first.first == pr.first.second)
              ps << pr.second.first << "/tcp";
            else
              ps << pr.second.first << "-" << pr.second.second << "/tcp";
          }
          for (size_t pi = 0; pi < optNet->inboundPortsUdp.size(); pi++) {
            if (ps.str().size() > 0 || pi > 0) ps << ",";
            auto &pr = optNet->inboundPortsUdp[pi];
            if (pr.first.first == pr.first.second)
              ps << pr.second.first << "/udp";
            else
              ps << pr.second.first << "-" << pr.second.second << "/udp";
          }
          e.ports = ps.str();
        }
        // Mounts
        auto numMounts = spec.dirsShare.size() + spec.filesShare.size();
        if (numMounts > 0)
          e.mounts = std::to_string(numMounts) + " share" + (numMounts > 1 ? "s" : "");
        // Healthcheck
        e.hasHealthcheck = (spec.healthcheck != nullptr);
      } catch (...) {
        // spec parse failure is not fatal for listing
      }
    }
    entries.push_back(e);
  }
  return entries;
}

static void listJson(const std::vector<CrateEntry> &entries) {
  std::cout << "[" << std::endl;
  for (size_t i = 0; i < entries.size(); i++) {
    auto &e = entries[i];
    std::cout << "  {";
    std::cout << "\"jid\":" << e.jid;
    std::cout << ",\"name\":\"" << e.name << "\"";
    std::cout << ",\"hostname\":\"" << e.hostname << "\"";
    std::cout << ",\"ip\":\"" << e.ip << "\"";
    std::cout << ",\"path\":\"" << e.path << "\"";
    std::cout << ",\"ports\":\"" << e.ports << "\"";
    std::cout << ",\"mounts\":\"" << e.mounts << "\"";
    std::cout << ",\"healthcheck\":" << (e.hasHealthcheck ? "true" : "false");
    std::cout << "}";
    if (i + 1 < entries.size()) std::cout << ",";
    std::cout << std::endl;
  }
  std::cout << "]" << std::endl;
}

static void listTable(const std::vector<CrateEntry> &entries) {
  if (entries.empty()) {
    std::cout << "No running crate containers." << std::endl;
    return;
  }

  // Calculate column widths
  size_t wJid = 3, wName = 4, wIp = 10, wHostname = 8, wPorts = 5, wMounts = 6;
  for (auto &e : entries) {
    wJid      = std::max(wJid, std::to_string(e.jid).size());
    wName     = std::max(wName, e.name.size());
    wIp       = std::max(wIp, e.ip.empty() ? size_t(1) : e.ip.size());
    wHostname = std::max(wHostname, e.hostname.size());
    wPorts    = std::max(wPorts, e.ports.empty() ? size_t(1) : e.ports.size());
    wMounts   = std::max(wMounts, e.mounts.empty() ? size_t(1) : e.mounts.size());
  }

  // Header
  std::cout << rang::style::bold
            << std::left
            << std::setw(wJid + 2) << "JID"
            << std::setw(wName + 2) << "NAME"
            << std::setw(wIp + 2) << "IP"
            << std::setw(wHostname + 2) << "HOSTNAME"
            << std::setw(wPorts + 2) << "PORTS"
            << std::setw(wMounts + 2) << "MOUNTS"
            << "HC"
            << rang::style::reset << std::endl;

  // Rows
  for (auto &e : entries) {
    std::cout << std::left
              << std::setw(wJid + 2) << e.jid
              << std::setw(wName + 2) << e.name
              << std::setw(wIp + 2) << (e.ip.empty() ? "-" : e.ip)
              << std::setw(wHostname + 2) << e.hostname
              << std::setw(wPorts + 2) << (e.ports.empty() ? "-" : e.ports)
              << std::setw(wMounts + 2) << (e.mounts.empty() ? "-" : e.mounts)
              << (e.hasHealthcheck ? "Y" : "-")
              << std::endl;
  }

  std::cout << std::endl
            << entries.size() << " running container" << (entries.size() != 1 ? "s" : "")
            << "." << std::endl;
}

bool listCrates(const Args &args) {
  auto entries = discoverRunningCrates();

  if (args.listJson)
    listJson(entries);
  else
    listTable(entries);

  return true;
}
