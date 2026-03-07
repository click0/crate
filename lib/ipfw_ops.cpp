// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// IPFW operations via raw socket with ipfw(8) fallback.
// The native API uses getsockopt/setsockopt with IP_FW3.

#include "ipfw_ops.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

#include <string>

#define ERR(msg...) ERR2("ipfw", msg)

namespace IpfwOps {

// TODO: Implement native IP_FW3 setsockopt API.
// The IPFW3 API is complex (variable-length opcodes, TLV format).
// For now, all operations use the ipfw(8) command as fallback.
// Native implementation is deferred to a future phase.

bool available() {
  return false; // No native implementation yet
}

void addRule(unsigned ruleNum, const std::string &rule) {
  std::vector<std::string> argv = {CRATE_PATH_IPFW, "add"};
  if (ruleNum > 0)
    argv.push_back(std::to_string(ruleNum));
  // Split rule into tokens
  std::istringstream iss(rule);
  std::string token;
  while (iss >> token)
    argv.push_back(token);
  Util::execCommand(argv, "add ipfw rule");
}

void deleteRule(unsigned ruleNum) {
  Util::execCommand({CRATE_PATH_IPFW, "delete", std::to_string(ruleNum)},
    "delete ipfw rule");
}

void deleteRulesInSet(unsigned setNum) {
  Util::execCommand({CRATE_PATH_IPFW, "delete", "set", std::to_string(setNum)},
    "delete ipfw rule set");
}

void configureNat(unsigned natInstance, const std::string &natConfig) {
  std::vector<std::string> argv = {CRATE_PATH_IPFW, "nat",
                                    std::to_string(natInstance), "config"};
  std::istringstream iss(natConfig);
  std::string token;
  while (iss >> token)
    argv.push_back(token);
  Util::execCommand(argv, "configure ipfw NAT");
}

void deleteNat(unsigned natInstance) {
  try {
    Util::execCommand({CRATE_PATH_IPFW, "nat", std::to_string(natInstance), "delete"},
      "delete ipfw NAT");
  } catch (...) {
    // NAT instance may not exist
  }
}

void addNatForJail(unsigned ruleNum, unsigned natInstance,
                   const std::string &jailIp, const std::string &extIface) {
  configureNat(natInstance, STR("if " << extIface << " same_ports unreg_only "
                                << "redirect_addr " << jailIp << " 0.0.0.0"));
  addRule(ruleNum, STR("nat " << natInstance << " ip from " << jailIp << " to any out"));
  addRule(ruleNum, STR("nat " << natInstance << " ip from any to me in"));
}

void addPortForward(unsigned ruleNum, unsigned natInstance,
                    const std::string &extIp, int extPort,
                    const std::string &jailIp, int jailPort,
                    const std::string &proto) {
  addRule(ruleNum, STR("fwd " << jailIp << "," << jailPort
                       << " " << proto << " from any to " << extIp << " " << extPort << " in"));
}

}
