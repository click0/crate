// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Per-user environment composer (0.9.12, rootless track).
//
// Aggregates the four namespacing pieces from 0.9.8-0.9.11 into a
// single PerUserEnv struct that callers (daemon route handlers,
// crate(1) bootstrapping) can request once and reuse:
//
//   - runtime paths from runtime_paths_pure (0.9.8)
//   - ZFS dataset prefix from zfs_dataset_pure (0.9.9)
//   - network sub-CIDRs (v4 + v6) from per_user_net_pure (0.9.10)
//   - RCTL loginclass + subject from per_user_rctl_pure (0.9.11)
//
// `composeForUid` takes the operator's uid and the rootless config
// knobs, produces the full env in one pass. Empty / opt-out fields
// in the config produce empty fields in the env (callers test
// emptiness rather than checking the toggle separately).
//
// This module is the contract the daemon-side wiring lands against
// in 0.9.13: when network_lease.cpp / RCTL handlers / loginclass
// rule application want to know "what's alice's stuff?" they call
// composeForUid(cfg, alice.uid) and read the struct.
//

#include <cstdint>
#include <string>

namespace PerUserEnvPure {

struct Config {
  // Master ZFS prefix; empty → no per-user ZFS split (legacy shape).
  std::string zfsMasterPrefix;

  // 1.1.15: master jail-path prefix. Each operator's permitted jail
  // paths sit under `<pathMasterPrefix>/<uid>/...`. Empty → no per-user
  // path split (legacy shape; the privops gate falls through to
  // bootstrap-Allow for create_jail).
  std::string pathMasterPrefix;

  // Master IPv4 CIDR + sub-prefix length. Empty master → no v4
  // sub-CIDR composition.
  std::string networkMasterCidr4;
  unsigned    networkSubPrefixLen4 = 24;

  // IPv6 equivalent. Empty disables.
  std::string networkMasterCidr6;
  unsigned    networkSubPrefixLen6 = 64;
};

struct Env {
  uint32_t uid = 0;

  // Runtime paths (always populated — even legacy mode wants
  // per-user audit log tail support eventually).
  std::string runtimeRoot;       // /var/run/crate/<uid>
  std::string leasesDir;
  std::string exportsDir;
  std::string importsDir;
  std::string auditLog;

  // ZFS dataset prefix. Empty if `cfg.zfsMasterPrefix` was empty.
  std::string zfsPrefix;

  // 1.1.15: jail-path prefix. Empty if `cfg.pathMasterPrefix` was empty.
  std::string pathPrefix;

  // Network sub-CIDRs. Empty if the corresponding master CIDR was
  // empty in the config.
  std::string ipv4SubCidr;
  std::string ipv6SubCidr;

  // RCTL umbrella loginclass + the subject tag for rctl(8) rules.
  std::string loginclass;          // crate-<uid>
  std::string loginclassSubject;   // loginclass:crate-<uid>
};

struct Result {
  Env env;
  // Empty on success. On error, partial env may be populated with
  // the fields that did compose; caller decides whether to surface
  // partial state or treat as full failure.
  std::string error;
};

// Compose the per-user environment. Validates uid (delegates to
// runtime_paths_pure::validateUid). Validates network master CIDRs
// (delegates to per_user_net_pure::compose*). Errors get joined
// into a single error string with field-prefix context
// (e.g. "ipv4: master IPv4 prefix > 32"); if multiple fields fail,
// the first error wins.
Result composeForUid(const Config &cfg, uint32_t uid);

} // namespace PerUserEnvPure
