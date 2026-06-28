// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "per_user_env_pure.h"

#include "per_user_net_pure.h"
#include "per_user_rctl_pure.h"
#include "runtime_paths_pure.h"
#include "zfs_dataset_pure.h"

namespace PerUserEnvPure {

Result composeForUid(const Config &cfg, uint32_t uid) {
  Result r;
  r.env.uid = uid;

  // Validate uid before composing paths (path encoders accept any
  // uint32_t but the upstream contract caps at INT32_MAX).
  if (auto e = RuntimePathsPure::validateUid((int64_t)uid); !e.empty()) {
    r.error = "uid: " + e;
    return r;
  }

  // Runtime paths — always populated.
  r.env.runtimeRoot = RuntimePathsPure::perUserRoot(uid);
  r.env.leasesDir   = RuntimePathsPure::perUserLeasesDir(uid);
  r.env.exportsDir  = RuntimePathsPure::perUserExportsDir(uid);
  r.env.importsDir  = RuntimePathsPure::perUserImportsDir(uid);
  r.env.auditLog    = RuntimePathsPure::perUserAuditLog(uid);

  // RCTL — always populated. The loginclass exists conceptually
  // even when the daemon hasn't yet added a /etc/login.conf entry
  // for it; the subject string drives rctl(8) regardless.
  r.env.loginclass        = PerUserRctlPure::loginclassName(uid);
  r.env.loginclassSubject = PerUserRctlPure::loginclassSubject(uid);

  // ZFS — opt-in via non-empty master prefix.
  if (!cfg.zfsMasterPrefix.empty()) {
    r.env.zfsPrefix = ZfsDatasetPure::composePerUserPrefix(
        cfg.zfsMasterPrefix, uid);
  }

  // 1.1.15: jail-path prefix — opt-in via non-empty master. Composition
  // mirrors the ZFS shape ("<master>/<uid>") and strips a single trailing
  // slash so callers can configure either "/jails" or "/jails/".
  if (!cfg.pathMasterPrefix.empty()) {
    std::string base = cfg.pathMasterPrefix;
    if (base.back() == '/') base.pop_back();
    r.env.pathMasterPrefix = base;                          // 1.1.17
    r.env.pathPrefix        = base + "/" + std::to_string(uid);
  }

  // IPv4 sub-CIDR — opt-in via non-empty master.
  if (!cfg.networkMasterCidr4.empty()) {
    auto v4 = PerUserNetPure::composeIpv4(cfg.networkMasterCidr4,
                                          cfg.networkSubPrefixLen4,
                                          uid);
    if (!v4.error.empty()) {
      r.error = "ipv4: " + v4.error;
      return r;
    }
    r.env.ipv4SubCidr = v4.cidr;
  }

  // IPv6 sub-CIDR.
  if (!cfg.networkMasterCidr6.empty()) {
    auto v6 = PerUserNetPure::composeIpv6(cfg.networkMasterCidr6,
                                          cfg.networkSubPrefixLen6,
                                          uid);
    if (!v6.error.empty()) {
      r.error = "ipv6: " + v6.error;
      return r;
    }
    r.env.ipv6SubCidr = v6.cidr;
  }

  return r;
}

} // namespace PerUserEnvPure
