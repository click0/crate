// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// MAC framework: ugidfw via ioctl, portacl via sysctl.

#include "mac_ops.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <sys/sysctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <sstream>

#define ERR(msg...) ERR2("mac", msg)

namespace MacOps {

void addUgidfwRule(const UgidfwRule &rule) {
  // Build ugidfw rule string
  std::ostringstream ss;
  ss << "add";
  if (rule.jailJid >= 0)
    ss << " subject jailid " << rule.jailJid;
  if (rule.subjectUid >= 0)
    ss << " subject uid " << rule.subjectUid;
  if (rule.objectUid >= 0)
    ss << " object uid " << rule.objectUid;
  if (!rule.objectPath.empty())
    ss << " object filesys " << rule.objectPath;
  ss << " mode ";
  if (rule.mode == 0)
    ss << "n";
  else {
    if (rule.mode & 4) ss << "r";
    if (rule.mode & 2) ss << "w";
    if (rule.mode & 1) ss << "x";
  }

  auto ruleStr = ss.str();

  // TODO: implement ioctl-based /dev/ugidfw access
  // For now, use the ugidfw(8) command
  Util::execCommand({CRATE_PATH_UGIDFW, ruleStr}, "add ugidfw rule");
}

void addUgidfwRuleRaw(const std::string &ruleStr) {
  auto ruleArgs = Util::splitString(ruleStr, " ");
  auto fullArgs = std::vector<std::string>{CRATE_PATH_UGIDFW, "add"};
  fullArgs.insert(fullArgs.end(), ruleArgs.begin(), ruleArgs.end());
  Util::execCommand(fullArgs, STR("add ugidfw rule: " << ruleStr));
}

void removeUgidfwRules(int jailJid) {
  // List rules, find matching jail, remove them
  std::vector<std::string> rules;
  listUgidfwRules(rules);

  auto jidStr = std::to_string(jailJid);
  for (size_t i = rules.size(); i > 0; i--) {
    auto &r = rules[i - 1];
    if (r.find(STR("jailid " << jidStr)) != std::string::npos) {
      try {
        Util::execCommand({CRATE_PATH_UGIDFW, "remove", std::to_string(i - 1)},
          "remove ugidfw rule");
      } catch (...) {}
    }
  }
}

void listUgidfwRules(std::vector<std::string> &output) {
  try {
    auto result = Util::execCommandGetOutput({CRATE_PATH_UGIDFW, "list"}, "list ugidfw rules");
    std::istringstream is(result);
    std::string line;
    while (std::getline(is, line))
      if (!line.empty())
        output.push_back(line);
  } catch (...) {}
}

void setPortaclRules(const std::vector<PortaclRule> &rules) {
  std::ostringstream ss;
  for (size_t i = 0; i < rules.size(); i++) {
    if (i > 0) ss << ",";
    ss << "uid:" << rules[i].uid << ":" << rules[i].proto << ":" << rules[i].port;
  }
  auto rulesStr = ss.str();
  Util::setSysctlInt("security.mac.portacl.suser_exempt", 1);

  // Use sysctlbyname to set portacl rules
  auto value = rulesStr;
  if (::sysctlbyname("security.mac.portacl.rules", nullptr, nullptr,
                      value.c_str(), value.size()) != 0) {
    // Fallback: sysctl command
    Util::execCommand({CRATE_PATH_SYSCTL, STR("security.mac.portacl.rules=" << rulesStr)},
      "set portacl rules");
  }
}

}
