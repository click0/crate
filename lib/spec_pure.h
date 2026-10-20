// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers extracted from lib/spec.cpp for unit testing.

#pragma once

#include <map>
#include <string>
#include <utility>

namespace SpecPure {

typedef std::pair<unsigned, unsigned> PortRange;

// 1.1.46: both ends must be 1..65535 and lo <= hi (a reversed `90-80`
// or port 0 / 70000 used to pass straight into pf/ipfw rule text).
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

// 1.1.46: bounded integer parsing for spec fields. `what` names the
// field in the error. Throws Exception (via ERR) outside [lo, hi] or on
// a non-integer; accepts a leading '-' (Util::toUInt does not, which
// made the documented `securelevel: -1` / `enforce_statfs: -1`
// unparseable).
int parseIntInRange(const std::string &s, int lo, int hi, const char *what);
// 1..65535 port number, same error style.
unsigned parsePort(const std::string &s, const char *what);

}
