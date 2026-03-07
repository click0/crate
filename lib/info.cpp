// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "locs.h"
#include "jail_query.h"
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
// Uses libjail API via JailQuery (replaces jls parsing).
static bool resolveContainer(const std::string &target, int &outJid, std::string &outPath,
                             std::string &outHostname, std::string &outIp) {
  auto cratePrefix = std::string(Locations::jailDirectoryPath) + "/jail-";

  // Try direct lookup by name first
  auto jail = JailQuery::getJailByName(target);
  if (!jail) {
    // Try lookup by JID
    try {
      int jid = std::stoi(target);
      jail = JailQuery::getJailByJid(jid);
    } catch (...) {}
  }

  // If direct lookup succeeded and it's a crate jail, use it
  if (jail && jail->path.find(cratePrefix) == 0) {
    outJid = jail->jid;
    outPath = jail->path;
    outHostname = jail->hostname;
    outIp = jail->ip4;
    return true;
  }

  // Fall back to scanning all crate jails for partial match
  auto jails = JailQuery::getAllJails(true /* crateOnly */);
  for (auto &j : jails) {
    auto name = j.path.substr(std::string(Locations::jailDirectoryPath).size() + 1);
    bool match = false;
    try { match = (std::stoi(target) == j.jid); } catch (...) {}
    if (!match) match = (name == target);
    if (!match) match = (name.find("jail-" + target) == 0);
    if (!match) match = (j.hostname == target);
    if (match) {
      outJid = j.jid;
      outPath = j.path;
      outHostname = j.hostname;
      outIp = j.ip4;
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

  // Show jail parameters via libjail API
  std::cout << std::endl;
  std::cout << rang::fg::green << "=== Jail Parameters ===" << rang::style::reset << std::endl;
  {
    auto ji = JailQuery::getJailByJid(jid);
    if (ji) {
      std::cout << "  name: " << ji->name << std::endl;
      std::cout << "  path: " << ji->path << std::endl;
      std::cout << "  hostname: " << ji->hostname << std::endl;
      std::cout << "  ip4: " << (ji->ip4.empty() ? "(none)" : ji->ip4) << std::endl;
      std::cout << "  dying: " << (ji->dying ? "true" : "false") << std::endl;
    } else {
      std::cout << "  (unable to retrieve jail parameters)" << std::endl;
    }
  }

  // Show network interfaces inside jail
  std::cout << std::endl;
  std::cout << rang::fg::green << "=== Network Interfaces ===" << rang::style::reset << std::endl;
  try {
    auto ifOutput = JailExec::execInJailGetOutput(
      jid, {CRATE_PATH_IFCONFIG, "-a"}, "root", "get jail interfaces");
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
    auto psOutput = JailExec::execInJailGetOutput(
      jid, {"/bin/ps", "auxww"}, "root", "list jail processes");
    std::istringstream pss(psOutput);
    std::string psline;
    while (std::getline(pss, psline))
      std::cout << "  " << psline << std::endl;
  } catch (...) {
    std::cout << "  (unable to list processes)" << std::endl;
  }

  return true;
}
