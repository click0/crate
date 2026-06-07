// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// crated configuration — parsed from /usr/local/etc/crated.conf (YAML).

#pragma once

#include "control_socket_pure.h"

#include <string>
#include <vector>

namespace Crated {

struct AuthToken {
  std::string name;
  std::string tokenHash;   // "sha256:<hex>"
  std::string role;         // "admin" or "viewer"
  // Expiry: UNIX epoch seconds. 0 means "never expires" — preserves
  // backward compatibility with existing crated.conf files that have
  // no expires_at field.
  long expiresAt = 0;
  // Scope: list of glob patterns matched against the request path.
  // Empty list means "no restriction" (any path the role allows).
  // Patterns: literal path or trailing `/*`. See AuthPure::pathInScope.
  //   ["/api/v1/containers", "/api/v1/containers/*"]
  std::vector<std::string> scope;
  // Pool ACL (added in 0.7.4): list of pool names the token may
  // touch. The pool of a container is inferred from the jail name
  // via PoolPure::inferPool. Empty = unrestricted (pre-0.7.4
  // behaviour). "*" = explicit all-pools grant.
  std::vector<std::string> pools;
};

struct Config {
  // Listen endpoints
  std::string unixSocket = "/var/run/crate/crated.sock";
  unsigned tcpPort = 9800;
  std::string tcpBind = "0.0.0.0";

  // 0.8.19: filesystem-perm gate on the unix socket. Empty owner/
  // group leaves the post-bind state at whatever the OS umask
  // produced (typically root:wheel). Operators tighten access by
  // setting `listen.unix_owner` / `listen.unix_group` /
  // `listen.unix_mode` in crated.conf. See SocketPermsPure for
  // validation; resolution of name -> uid/gid happens at startup.
  std::string unixSocketOwner;
  std::string unixSocketGroup;
  unsigned    unixSocketMode = 0660;

  // TLS (for TCP listener)
  std::string tlsCert;
  std::string tlsKey;
  std::string tlsCa;        // CA for mTLS client verification
  bool requireClientCert = false;

  // Authentication
  std::vector<AuthToken> tokens;
  // Separator used by PoolPure::inferPool to extract pool from a
  // jail name. Default '-'. A single byte; YAML key
  // `auth.pool_separator: "-"`. Operators who already have hyphens
  // inside container names can use `_` or `.`.
  char poolSeparator = '-';

  // Logging
  std::string logFile = "/var/log/crated.log";
  std::string logLevel = "info";

  // WebSocket console (opt-in: 0 disables). Handshakes are
  // authenticated via `Authorization: Bearer <admin-token>`.
  unsigned consoleWsPort = 0;
  std::string consoleWsBind = "127.0.0.1";

  // Control sockets (opt-in, 0.7.10): per-group Unix sockets for
  // bearer-token-less GUI/tray access. Each socket has its own
  // file mode + group + pool ACL + role. See ControlSocketPure.
  std::vector<ControlSocketPure::ControlSocketSpec> controlSockets;

  // 0.9.12: rootless per-user namespacing master toggle.
  //
  // When true, runtime helpers (paths, ZFS dataset prefix, network
  // sub-CIDR, RCTL umbrella loginclass) compose their results from
  // the connecting operator's uid. When false, every helper falls
  // back to legacy single-tenant shape so existing 0.8.x deployments
  // are byte-identical.
  //
  // 0.9.30: DEFAULT FLIPPED to true. New installs (and old installs
  // whose crated.conf doesn't set this field explicitly) now run
  // in rootless mode. Operators wanting the legacy single-tenant
  // path must add `rootless_per_user: false` to crated.conf
  // explicitly. See docs/rootless-migration.md "Rolling back" for
  // the procedure.
  bool rootlessPerUser = true;

  // Master ZFS prefix; per-user datasets land under
  // `<zfsMasterPrefix>/<uid>/<jail>`. Empty string means "no
  // per-user split — use the legacy `<pool>/jails/<jail>` shape".
  // See ZfsDatasetPure::composePerUserDataset.
  std::string zfsMasterPrefix;

  // 1.1.15: master jail-path prefix. Per-user jail paths must sit
  // under `<pathMasterPrefix>/<uid>/...`. Empty -> no per-user path
  // split; the privops gate falls through to bootstrap-Allow for
  // create_jail. Set this to enforce path ownership on create_jail
  // (PrivOpsAuthzPure::Decision::DenyForeignCreatePath on a foreign
  // target).
  std::string pathMasterPrefix;

  // Master IPv4 CIDR + sub-prefix length for per-user network
  // allocation. See PerUserNetPure::composeIpv4. Empty master
  // disables v4 per-user (operator can still use v6).
  std::string networkMasterCidr4;
  unsigned    networkSubPrefixLen4 = 24;

  // IPv6 equivalent. Empty disables.
  std::string networkMasterCidr6;
  unsigned    networkSubPrefixLen6 = 64;

  // 0.9.14: Unix-socket listener for libnv-based privops IPC.
  // Empty path disables the listener (existing /api/v1/privops/:verb
  // HTTP path remains for remote clients). When set, crated opens
  // an AF_UNIX socket at this path (mode 0660 root:<group>) and
  // accepts nvlist-encoded privops requests. Per-connection
  // getpeereid extracts the operator uid which feeds the per-user
  // audit hook from 0.9.13. See daemon/privops_listener.cpp.
  std::string privopsSocketPath;
  std::string privopsSocketGroup;
  unsigned    privopsSocketMode = 0660;

  // 0.9.29: per-loginclass RCTL umbrella defaults. When non-empty
  // AND a create_jail privops verb is invoked over the libnv
  // socket (peer uid > 0), the daemon auto-applies these RCTL
  // rules to the operator's `crate-<uid>` loginclass after the
  // jail is created. Idempotent — re-applying the same rule is
  // a no-op at the kernel.
  //
  // Example crated.conf:
  //   rctl_umbrella:
  //     memoryuse: 4G
  //     pcpu: 200
  //     maxproc: 256
  //
  // Keys / values are validated via the existing RetunePure
  // whitelist at config-load time; bad entries throw at startup.
  std::vector<std::pair<std::string, std::string>> rctlUmbrella;

  // Load from YAML file
  static Config load(const std::string &path);
};

}
