// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers extracted from lib/spec.cpp for unit testing.

#pragma once

#include <map>
#include <string>
#include <utility>

namespace SpecPure {

typedef std::pair<unsigned, unsigned> PortRange;

PortRange parsePortRange(const std::string &str);

// Replace ${KEY} tokens in `input` with values from `vars`.
// No-op if vars is empty. Substitution is multi-pass per key.
std::string substituteVars(const std::string &input,
                           const std::map<std::string, std::string> &vars);

// 0.8.17: top-level `network:` shorthand. Returns "" if the supplied
// value is supported (currently only "auto"), or a diagnostic
// otherwise. Reserved for future shortcuts: "bridge0", "host", ...
//   network: auto      # vnet jail, auto-create bridge, auto-allocate IP
std::string validateTopLevelNetwork(const std::string &v);

// 1.1.44: options/net address fields were stored unvalidated and only
// blew up (or did something undefined) in run_net.cpp at jail start.
// "" on success, otherwise a one-line reason.
//   static IPv4: "a.b.c.d" or "a.b.c.d/0..32"
//   static IPv6: "<v6>" or "<v6>/0..128"
//   gateway:     bare IPv4 address
std::string validateStaticIp4(const std::string &v);
std::string validateStaticIp6(const std::string &v);
std::string validateGateway4(const std::string &v);

}
