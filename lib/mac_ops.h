// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// MAC framework operations: ugidfw (mac_bsdextended) via ioctl,
// mac_portacl via sysctl. Replaces ugidfw(8) shell calls.

#pragma once

#include <string>
#include <vector>

namespace MacOps {

// mac_bsdextended (ugidfw) rule management via /dev/ugidfw ioctl.
// Falls back to ugidfw(8) command if ioctl fails.

struct UgidfwRule {
  int jailJid = -1;      // -1 = not jail-specific
  int subjectUid = -1;   // -1 = any
  int objectUid = -1;    // -1 = any
  std::string objectPath; // empty = any
  int mode = 0;          // bitmask: 0 = deny all
};

void addUgidfwRule(const UgidfwRule &rule);
void removeUgidfwRules(int jailJid);
void listUgidfwRules(std::vector<std::string> &output);

// mac_portacl via sysctl
struct PortaclRule {
  int uid;
  std::string proto;     // "tcp" or "udp"
  int port;
};

void setPortaclRules(const std::vector<PortaclRule> &rules);

}
