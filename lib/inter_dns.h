// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Runtime side of the global inter-container DNS service. Walks
// JailQuery for all crate-managed jails, asks lib/inter_dns_pure to
// render the zone, and writes the result to two well-known files:
//
//   /etc/hosts                                — replace the
//       crate-marker block; safe for resolvers that fall through to
//       /etc/hosts (the BSD default).
//   /usr/local/etc/unbound/conf.d/crate.conf — atomic write,
//       triggers `service unbound reload` if the daemon is running.
//
// The runtime does not start its own DNS server — it produces config
// files that an existing unbound (or the BSD resolver via /etc/hosts)
// consumes.
//

#include <string>

namespace InterDns {

struct RebuildResult {
  unsigned entries = 0;       // jails included
  bool wroteHosts  = false;
  bool wroteUnbound = false;
  bool reloadedUnbound = false;
  std::string hostsPath;
  std::string unboundPath;
};

// Rebuild both files from live JailQuery state. Pass an empty
// `unboundPath` to skip unbound integration; pass an empty
// `hostsPath` to skip /etc/hosts integration.
RebuildResult rebuild(const std::string &hostsPath = "/etc/hosts",
                      const std::string &unboundPath
                        = "/usr/local/etc/unbound/conf.d/crate.conf",
                      bool reloadUnbound = true);

} // namespace InterDns
