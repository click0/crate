// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// mac_portacl rule-list arithmetic (1.1.44) — pure.
//
// security.mac.portacl.rules is ONE host-wide sysctl holding a
// comma-separated list ("uid:0:tcp:80,uid:0:udp:80,..."). crate used
// to overwrite it with the current container's allow-list, clobbering
// every other container's (and the operator's) rules, and never put
// anything back. These helpers merge a container's rules into the
// existing list on start and take exactly those rules out again on
// stop, leaving everything else untouched.

#pragma once

#include <string>
#include <vector>

namespace MacPure {

// "uid:<uid>:<proto>:<port>" — the portacl rule token crate emits.
std::string formatPortaclRule(int uid, const std::string &proto, int port);

// Split a sysctl value into rule tokens: comma-separated, empty tokens
// and surrounding whitespace dropped, order kept, duplicates kept.
std::vector<std::string> splitPortaclRules(const std::string &value);

// `current` with every rule in `ours` appended once (rules already
// present are not duplicated). Returns the new sysctl value.
std::string mergePortaclRules(const std::string &current,
                              const std::vector<std::string> &ours);

// `current` with every occurrence of each rule in `ours` removed.
// Rules that other containers or the operator added stay.
std::string removePortaclRules(const std::string &current,
                               const std::vector<std::string> &ours);

} // namespace MacPure
