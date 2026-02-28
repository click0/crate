// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include "args.h"
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
    // check for +CRATE.SPEC
    auto specPath = e.path + "/+CRATE.SPEC";
    if (Util::Fs::fileExists(specPath))
      e.specFile = specPath;
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
  size_t wJid = 3, wName = 4, wIp = 10, wHostname = 8, wPath = 4;
  for (auto &e : entries) {
    wJid      = std::max(wJid, std::to_string(e.jid).size());
    wName     = std::max(wName, e.name.size());
    wIp       = std::max(wIp, e.ip.empty() ? size_t(1) : e.ip.size());
    wHostname = std::max(wHostname, e.hostname.size());
    wPath     = std::max(wPath, e.path.size());
  }

  // Header
  std::cout << rang::style::bold
            << std::left
            << std::setw(wJid + 2) << "JID"
            << std::setw(wName + 2) << "Name"
            << std::setw(wIp + 2) << "IP Address"
            << std::setw(wHostname + 2) << "Hostname"
            << "Path"
            << rang::style::reset << std::endl;

  // Rows
  for (auto &e : entries) {
    std::cout << std::left
              << std::setw(wJid + 2) << e.jid
              << std::setw(wName + 2) << e.name
              << std::setw(wIp + 2) << (e.ip.empty() ? "-" : e.ip)
              << std::setw(wHostname + 2) << e.hostname
              << e.path
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
