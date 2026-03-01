// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "locs.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define ERR(msg...) \
  ERR2("info", msg)

// Resolve a container target (name or JID) to its jail path and JID.
// Searches jls output for crate jails matching the target.
static bool resolveContainer(const std::string &target, int &outJid, std::string &outPath,
                             std::string &outHostname, std::string &outIp) {
  std::string output;
  try {
    output = Util::execCommandGetOutput({CRATE_PATH_JLS, "-N"}, "list jails");
  } catch (...) {
    return false;
  }

  auto cratePrefix = std::string(Locations::jailDirectoryPath) + "/jail-";
  std::istringstream is(output);
  std::string line;
  bool header = true;
  while (std::getline(is, line)) {
    if (header) { header = false; continue; }
    if (line.empty()) continue;
    std::istringstream ls(line);
    int jid;
    std::string ip, hostname, path;
    ls >> jid >> ip >> hostname >> path;
    if (path.find(cratePrefix) != 0)
      continue;
    auto name = path.substr(std::string(Locations::jailDirectoryPath).size() + 1);
    // Match by JID, full name, or partial name (jail-SPECNAME-*)
    bool match = false;
    try { match = (std::stoi(target) == jid); } catch (...) {}
    if (!match) match = (name == target);
    if (!match) match = (name.find("jail-" + target) == 0);
    if (!match) match = (hostname == target);
    if (match) {
      outJid = jid;
      outPath = path;
      outHostname = hostname;
      outIp = (ip == "-") ? "" : ip;
      return true;
    }
  }
  return false;
}

// Print a labeled field
static void field(const std::string &label, const std::string &value) {
  std::cout << rang::style::bold << std::left
            << label << ": " << rang::style::reset << value << std::endl;
}

bool infoCrate(const Args &args) {
  int jid;
  std::string path, hostname, ip;

  if (!resolveContainer(args.infoTarget, jid, path, hostname, ip))
    ERR("container '" << args.infoTarget << "' not found (not running or not a crate jail)")

  auto jidStr = std::to_string(jid);

  std::cout << rang::fg::green << "=== Container Info ===" << rang::style::reset << std::endl;
  field("  JID", jidStr);
  field("  Path", path);
  field("  Hostname", hostname);
  field("  IP Address", ip.empty() ? "(none)" : ip);

  // Show spec info if available
  auto specPath = path + "/+CRATE.SPEC";
  if (Util::Fs::fileExists(specPath))
    field("  Spec", specPath);

  // Show mount points from jls
  std::cout << std::endl;
  std::cout << rang::fg::green << "=== Jail Parameters ===" << rang::style::reset << std::endl;
  try {
    auto params = Util::execCommandGetOutput(
      {CRATE_PATH_JLS, "-j", jidStr, "-N"},
      "get jail parameters");
    // Print each line indented
    std::istringstream ps(params);
    std::string pline;
    while (std::getline(ps, pline))
      std::cout << "  " << pline << std::endl;
  } catch (...) {
    std::cout << "  (unable to retrieve jail parameters)" << std::endl;
  }

  // Show network interfaces inside jail
  std::cout << std::endl;
  std::cout << rang::fg::green << "=== Network Interfaces ===" << rang::style::reset << std::endl;
  try {
    auto ifOutput = Util::execCommandGetOutput(
      {CRATE_PATH_JEXEC, jidStr, CRATE_PATH_IFCONFIG, "-a"},
      "get jail interfaces");
    std::istringstream ifs(ifOutput);
    std::string ifline;
    while (std::getline(ifs, ifline))
      std::cout << "  " << ifline << std::endl;
  } catch (...) {
    std::cout << "  (unable to retrieve network interfaces)" << std::endl;
  }

  // Show RCTL limits if any
  std::cout << std::endl;
  std::cout << rang::fg::green << "=== Resource Limits (RCTL) ===" << rang::style::reset << std::endl;
  try {
    auto rctlOutput = Util::execCommandGetOutput(
      {CRATE_PATH_RCTL, "-h", STR("jail:" << jidStr)},
      "get RCTL limits");
    if (rctlOutput.empty() || rctlOutput == "\n") {
      std::cout << "  (none)" << std::endl;
    } else {
      std::istringstream rs(rctlOutput);
      std::string rline;
      while (std::getline(rs, rline))
        std::cout << "  " << rline << std::endl;
    }
  } catch (...) {
    std::cout << "  (RCTL not available)" << std::endl;
  }

  // Show processes in jail
  std::cout << std::endl;
  std::cout << rang::fg::green << "=== Processes ===" << rang::style::reset << std::endl;
  try {
    auto psOutput = Util::execCommandGetOutput(
      {CRATE_PATH_JEXEC, jidStr, "/bin/ps", "auxww"},
      "list jail processes");
    std::istringstream pss(psOutput);
    std::string psline;
    while (std::getline(pss, psline))
      std::cout << "  " << psline << std::endl;
  } catch (...) {
    std::cout << "  (unable to list processes)" << std::endl;
  }

  return true;
}
