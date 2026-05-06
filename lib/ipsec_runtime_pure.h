// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for the runtime side of IPsec / strongSwan integration.
// Sister of lib/wireguard_runtime_pure.h.
//
// Spec section:
//
//   options:
//     ipsec:
//       conn: my-tunnel-1
//
// At `crate run` time, the runtime invokes
//
//   ipsec auto --add  <conn>
//   ipsec auto --up   <conn>
//
// before the jail is started and registers a RunAtEnd handler that
// invokes
//
//   ipsec auto --down   <conn>
//   ipsec auto --delete <conn>
//
// on container teardown — so a crash mid-run() leaves no orphan SA.
//
// Prerequisites the operator owns (NOT crate's responsibility):
//   - strongSwan is installed and the daemon is running.
//   - The conn block referenced by `conn:` is already in
//     /usr/local/etc/ipsec.conf (or an included file). Operators
//     who want to generate that file can pipe `crate vpn ipsec
//     render-conf <spec.yml>` into the include directory; the
//     render-conf side closes the validate+render half (see
//     lib/ipsec_pure.h, 0.6.10), and this module closes the
//     runtime half — together they form the full picture.
//
// All actual fork/exec lives in lib/run.cpp via Util::execCommand;
// nothing here touches the filesystem or the network.
//

#include <string>
#include <vector>

namespace IpsecRuntimePure {

// Validate a `conn:` value from the spec. Reuses the same alphabet
// as IpsecPure::validateConnName (ASCII alnum + ._-, length 1..32,
// %default reserved) so a spec that round-trips through render-conf
// can pass the same conn name to the runtime hook.
//
// Returns "" if acceptable; otherwise a one-line reason for
// `crate validate`.
std::string validateConnName(const std::string &name);

// Build the argv for `ipsec auto --add <name>`. The first element
// is the absolute path to the strongSwan ipsec wrapper on FreeBSD
// (`/usr/local/sbin/ipsec`) so the runtime doesn't depend on PATH.
std::vector<std::string> buildAddArgv(const std::string &connName);

// `ipsec auto --up <name>` — initiates SA negotiation.
std::vector<std::string> buildUpArgv(const std::string &connName);

// `ipsec auto --down <name>` — terminates SA.
std::vector<std::string> buildDownArgv(const std::string &connName);

// `ipsec auto --delete <name>` — removes the conn from the
// daemon's loaded set. Symmetric counterpart to --add.
std::vector<std::string> buildDeleteArgv(const std::string &connName);

// True iff the spec section is "active" — `connName` non-empty.
bool isEnabled(const std::string &connName);

} // namespace IpsecRuntimePure
