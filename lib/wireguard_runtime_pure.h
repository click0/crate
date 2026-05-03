// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for the runtime side of WireGuard integration.
//
// Spec section:
//
//   options:
//     wireguard:
//       config: /usr/local/etc/wireguard/wg0.conf
//
// At `crate run` time, the runtime invokes `wg-quick up <config>`
// before the jail is started, and registers a RunAtEnd handler that
// calls `wg-quick down <config>` on container teardown — so a
// crash in the middle of run() leaves no orphan tunnel.
//
// This module owns just the validation + argv-building decisions.
// All actual fork/exec lives in lib/wireguard_runtime.cpp; nothing
// here touches the filesystem or the network.
//

#include <string>
#include <vector>

namespace WireguardRuntimePure {

// Validate a `config:` path from the spec. Rules:
//   - non-empty, ≤ 255 chars
//   - must be absolute (`/...`) — wg-quick(8) takes either a path
//     OR a tunnel name; we always pass it the path so the spec is
//     unambiguous.
//   - must NOT contain shell metacharacters (`;`, `` ` ``, `$`,
//     `|`, `&`, `<`, `>`, `\\`, `\n`, `\r`).
//   - must NOT contain `..` segments — defense against config
//     traversal even though the daemon reads as root.
// Returns "" if acceptable; otherwise a one-line reason for
// `crate validate`.
std::string validateConfigPath(const std::string &path);

// Build the argv for `wg-quick up <path>`. The first element is
// the absolute path to the wg-quick binary on FreeBSD
// (/usr/local/bin/wg-quick) so the runtime doesn't depend on PATH.
std::vector<std::string> buildUpArgv(const std::string &configPath);

// Build the argv for `wg-quick down <path>`.
std::vector<std::string> buildDownArgv(const std::string &configPath);

// True iff the spec section is "active" — i.e. configPath is
// non-empty after spec validation. Convenience for callers that
// would otherwise duplicate the empty check.
bool isEnabled(const std::string &configPath);

} // namespace WireguardRuntimePure
