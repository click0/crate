// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "spec.h"
#include "locs.h"
#include "jail_query.h"
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

#include "list_pure.h"

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

// Discover running crate jails using libjail API (replaces jls parsing).
static std::vector<CrateEntry> discoverRunningCrates() {
  std::vector<CrateEntry> entries;

  auto jails = JailQuery::getAllJails(true /* crateOnly */);
  for (auto &j : jails) {
    CrateEntry e;
    e.jid = j.jid;
    e.path = j.path;
    e.hostname = j.hostname;
    e.ip = j.ip4;
    e.name = j.name.empty()
      ? j.path.substr(std::string(Locations::jailDirectoryPath).size() + 1)
      : j.name;

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

// listJson, listTable moved to lib/list_pure.cpp. This file's CrateEntry
// struct is the discovery-side type; convert to ListPure::Entry when
// rendering.
static std::vector<ListPure::Entry> toPureEntries(const std::vector<CrateEntry> &src) {
  std::vector<ListPure::Entry> out;
  out.reserve(src.size());
  for (auto &e : src)
    out.push_back({e.jid, e.name, e.path, e.ip, e.hostname, e.ports, e.mounts, e.hasHealthcheck});
  return out;
}

static void listJson(const std::vector<CrateEntry> &entries) {
  ListPure::renderJson(std::cout, toPureEntries(entries));
}

static void listTable(const std::vector<CrateEntry> &entries) {
  // ListPure::renderTable handles bold-header decoration omission for
  // testability; bold here for terminal aesthetics.
  if (!entries.empty())
    std::cout << rang::style::bold;
  ListPure::renderTable(std::cout, toPureEntries(entries));
  if (!entries.empty())
    std::cout << rang::style::reset;
}

bool listCrates(const Args &args) {
  auto entries = discoverRunningCrates();

  if (args.listJson)
    listJson(entries);
  else
    listTable(entries);

  return true;
}
