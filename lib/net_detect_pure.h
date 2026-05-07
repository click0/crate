// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for default-route interface detection (0.8.6).
//
// 0.8.0's auto-fw needs `network_interface` from crate.yml to know
// where to NAT outbound traffic. Until 0.8.6 operators had to set
// it manually; 0.8.6 falls back to auto-detection via FreeBSD's
// route(8):
//
//   $ route -4 get default
//      route to: default
//   destination: default
//          mask: default
//       gateway: 192.168.1.1
//           fib: 0
//     interface: em0
//         flags: <UP,GATEWAY,DONE,STATIC>
//   recvpipe  sendpipe  ssthresh  rtt,msec    mtu        weight    expire
//        0         0         0         0      1500         1         0
//
// We just need the line "interface: <name>". This module is the
// parser; the actual fork+exec lives in lib/net_detect.cpp.
//

#include <string>

namespace NetDetectPure {

// Parse the output of `route -4 get default` and extract the
// interface name. Returns the iface name on success, "" on failure
// (no interface line, malformed input, or "default" route absent).
//
// Robust against:
//   - leading whitespace before "interface:"
//   - tabs vs spaces (route(8) uses spaces; we accept either)
//   - trailing whitespace / CRLF
//   - localised output (English-only token "interface:")
//
// If multiple "interface:" lines appear (shouldn't happen with
// standard route output), takes the FIRST.
std::string parseRouteOutput(const std::string &out);

} // namespace NetDetectPure
