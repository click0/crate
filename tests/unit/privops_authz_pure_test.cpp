// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_authz_pure.h"

#include <atf-c++.hpp>

#include <string>

using PrivOpsAuthzPure::Decision;
using PrivOpsAuthzPure::authorize;
using PrivOpsAuthzPure::datasetOwned;
using PrivOpsAuthzPure::decisionReason;
using PrivOpsAuthzPure::pathOwned;
using PrivOpsPure::Verb;

namespace {

// An Env scoped to uid 1000 with a per-user ZFS split configured.
PerUserEnvPure::Env env1000() {
  PerUserEnvPure::Env e;
  e.uid              = 1000;
  e.zfsPrefix        = "zroot/crate-tenants/1000";
  e.pathMasterPrefix = "/jails-tenants";        // 1.1.17
  e.pathPrefix       = "/jails-tenants/1000";   // 1.1.15
  e.loginclass       = "crate-1000";
  return e;
}

} // namespace

// --- datasetOwned ---

ATF_TEST_CASE_WITHOUT_HEAD(dataset_owned_prefix_and_descendants);
ATF_TEST_CASE_BODY(dataset_owned_prefix_and_descendants) {
  const std::string p = "zroot/crate-tenants/1000";
  ATF_REQUIRE(datasetOwned(p, p));                              // prefix root
  ATF_REQUIRE(datasetOwned(p + "/web", p));                     // descendant
  ATF_REQUIRE(datasetOwned(p + "/web/data", p));                // nested deeper
}

ATF_TEST_CASE_WITHOUT_HEAD(dataset_owned_rejects_foreign_and_substring);
ATF_TEST_CASE_BODY(dataset_owned_rejects_foreign_and_substring) {
  const std::string p = "zroot/crate-tenants/1000";
  ATF_REQUIRE(!datasetOwned("zroot/crate-tenants/1001/web", p)); // other uid
  ATF_REQUIRE(!datasetOwned("zroot/other/1000", p));             // other master
  // Slash-anchored: a longer uid that shares the prefix string must
  // not pass (".../1000" must not own ".../10001").
  ATF_REQUIRE(!datasetOwned("zroot/crate-tenants/10001", p));
  ATF_REQUIRE(!datasetOwned("zroot/crate-tenants/1000extra", p));
}

ATF_TEST_CASE_WITHOUT_HEAD(dataset_owned_empty_prefix_allows_all);
ATF_TEST_CASE_BODY(dataset_owned_empty_prefix_allows_all) {
  // No per-user ZFS split configured → nothing to gate.
  ATF_REQUIRE(datasetOwned("anything/at/all", ""));
  ATF_REQUIRE(datasetOwned("", ""));
}

// --- authorize: dataset verbs ---

ATF_TEST_CASE_WITHOUT_HEAD(authorize_attach_zfs_own_dataset);
ATF_TEST_CASE_BODY(authorize_attach_zfs_own_dataset) {
  auto e = env1000();
  ATF_REQUIRE(authorize(Verb::AttachZfs, "zroot/crate-tenants/1000/web", "", e)
              == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::DetachZfs, "zroot/crate-tenants/1000/web", "", e)
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_attach_zfs_foreign_dataset_denied);
ATF_TEST_CASE_BODY(authorize_attach_zfs_foreign_dataset_denied) {
  auto e = env1000();
  ATF_REQUIRE(authorize(Verb::AttachZfs, "zroot/crate-tenants/1001/web", "", e)
              == Decision::DenyForeignDataset);
  ATF_REQUIRE(authorize(Verb::DetachZfs, "zroot/crate-tenants/1001/web", "", e)
              == Decision::DenyForeignDataset);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_dataset_unconfigured_split_allows);
ATF_TEST_CASE_BODY(authorize_dataset_unconfigured_split_allows) {
  // rootless on but no zfsMasterPrefix → env.zfsPrefix empty → allow.
  PerUserEnvPure::Env e;
  e.uid        = 1000;
  e.loginclass = "crate-1000";
  ATF_REQUIRE(authorize(Verb::AttachZfs, "zroot/anyones/dataset", "", e)
              == Decision::Allow);
}

// --- authorize: loginclass verbs ---

ATF_TEST_CASE_WITHOUT_HEAD(authorize_loginclass_own_umbrella);
ATF_TEST_CASE_BODY(authorize_loginclass_own_umbrella) {
  auto e = env1000();
  ATF_REQUIRE(authorize(Verb::SetLoginclassRctl, "", "crate-1000", e)
              == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::ClearLoginclassRctl, "", "crate-1000", e)
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_loginclass_foreign_denied);
ATF_TEST_CASE_BODY(authorize_loginclass_foreign_denied) {
  auto e = env1000();
  ATF_REQUIRE(authorize(Verb::SetLoginclassRctl, "", "crate-1001", e)
              == Decision::DenyForeignLoginclass);
  ATF_REQUIRE(authorize(Verb::ClearLoginclassRctl, "", "system", e)
              == Decision::DenyForeignLoginclass);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_loginclass_empty_fails_closed);
ATF_TEST_CASE_BODY(authorize_loginclass_empty_fails_closed) {
  // A missing loginclass field can't match crate-<uid> → deny.
  auto e = env1000();
  ATF_REQUIRE(authorize(Verb::SetLoginclassRctl, "", "", e)
              == Decision::DenyForeignLoginclass);
}

// --- authorize: ungated verbs return Allow ---

ATF_TEST_CASE_WITHOUT_HEAD(authorize_host_global_verbs_allowed);
ATF_TEST_CASE_BODY(authorize_host_global_verbs_allowed) {
  auto e = env1000();
  // Host-global verbs are not pool-scoped; they pass the per-user gate
  // (still group-gated at the socket; host-wide by design).
  ATF_REQUIRE(authorize(Verb::AddPfRule, "", "", e)        == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::AddIpfwRule, "", "", e)      == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::CreateEpair, "", "", e)      == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::ConfigureIface, "", "", e)   == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::ConfigureIpfwNat, "", "", e) == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_jid_scoped_under_null_lookup_allows);
ATF_TEST_CASE_BODY(authorize_jid_scoped_under_null_lookup_allows) {
  // 1.1.13 backward-compatibility: the 4-arg authorize() wrapper passes
  // PrivOpsAuthzPure::nullLookup(), which reports every jid/name as
  // unknown. Unknown targets are treated as the bootstrap concession
  // (jails predating 1.1.13 aren't in the registry yet) -> Allow.
  // Legitimate pre-1.1.13 rootless operations must keep working.
  //
  // CreateJail is intentionally NOT in this list: 1.1.15 gates it on
  // env.pathPrefix (a *config* prefix, not a registry lookup), so the
  // 4-arg wrapper with an empty req.path against env1000() (which has
  // pathPrefix populated) now correctly denies. The
  // authorize_create_jail_* tests below pin that new behavior.
  auto e = env1000();
  ATF_REQUIRE(authorize(Verb::SetRctl,        "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::ClearRctl,      "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::SignalJail,     "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::SetJailCpuset,  "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::QueryJailRctl,  "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::DestroyJail,    "", "", e) == Decision::Allow);
}

// --- 1.1.13: jid/name-scoped gating via OwnerLookup ---

namespace {

using PrivOpsAuthzPure::Owner;
using PrivOpsAuthzPure::OwnerLookup;
using PrivOpsAuthzPure::Request;

// Lookup that knows exactly one (jid, name, path) -> uid mapping.
// Useful for driving the gate without pulling in the impure registry.
OwnerLookup fixedOwner(unsigned ownedJid, const std::string &ownedName,
                       uint32_t ownerUid,
                       const std::string &ownedPath = "") {
  OwnerLookup l;
  l.byJid = [ownedJid, ownerUid](unsigned jid) -> Owner {
    Owner o;
    if (jid == ownedJid) { o.known = true; o.uid = ownerUid; }
    return o;
  };
  l.byName = [ownedName, ownerUid](const std::string &name) -> Owner {
    Owner o;
    if (name == ownedName) { o.known = true; o.uid = ownerUid; }
    return o;
  };
  l.byPath = [ownedPath, ownerUid](const std::string &p) -> Owner {
    Owner o;
    if (ownedPath.empty()) return o;
    const bool exact      = (p == ownedPath);
    const bool descendant = (p.size() > ownedPath.size()
                          && p.compare(0, ownedPath.size(), ownedPath) == 0
                          && p[ownedPath.size()] == '/');
    if (exact || descendant) { o.known = true; o.uid = ownerUid; }
    return o;
  };
  return l;
}

Request reqJid(unsigned j) { Request r; r.jid = j; return r; }
Request reqName(std::string n) { Request r; r.jailName = std::move(n); return r; }
Request reqPath(std::string p) { Request r; r.path = std::move(p); return r; }

} // namespace

ATF_TEST_CASE_WITHOUT_HEAD(authorize_jid_unknown_target_allowed_bootstrap);
ATF_TEST_CASE_BODY(authorize_jid_unknown_target_allowed_bootstrap) {
  // A jid not in the registry pre-dates 1.1.13 - bootstrap concession.
  auto e = env1000();
  auto l = fixedOwner(/*ownedJid=*/77, /*ownedName=*/"web", /*ownerUid=*/1000);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::SignalJail,    reqJid(123), e, l)
              == Decision::Allow);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::SetRctl,       reqJid(123), e, l)
              == Decision::Allow);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::QueryJailRctl, reqJid(123), e, l)
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_jid_own_target_allowed);
ATF_TEST_CASE_BODY(authorize_jid_own_target_allowed) {
  auto e = env1000();
  auto l = fixedOwner(77, "web", 1000);   // owned by the caller
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::SignalJail,    reqJid(77), e, l)
              == Decision::Allow);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::SetJailCpuset, reqJid(77), e, l)
              == Decision::Allow);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::ClearRctl,     reqJid(77), e, l)
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_jid_foreign_owner_denied);
ATF_TEST_CASE_BODY(authorize_jid_foreign_owner_denied) {
  // Hostile operator (uid 1000) targets jid 77 which is owned by 1001.
  // Every jid-keyed verb must deny.
  auto e = env1000();
  auto l = fixedOwner(77, "web", /*ownerUid=*/1001);
  for (Verb v : {Verb::SignalJail, Verb::SetRctl, Verb::ClearRctl,
                 Verb::SetJailCpuset, Verb::QueryJailRctl}) {
    ATF_REQUIRE(PrivOpsAuthzPure::authorize(v, reqJid(77), e, l)
                == Decision::DenyForeignJid);
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_destroy_jail_own_name_allowed);
ATF_TEST_CASE_BODY(authorize_destroy_jail_own_name_allowed) {
  auto e = env1000();
  auto l = fixedOwner(77, "web", 1000);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::DestroyJail, reqName("web"), e, l)
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_destroy_jail_foreign_name_denied);
ATF_TEST_CASE_BODY(authorize_destroy_jail_foreign_name_denied) {
  auto e = env1000();
  auto l = fixedOwner(77, "web", /*ownerUid=*/1001);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::DestroyJail, reqName("web"), e, l)
              == Decision::DenyForeignJailName);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_destroy_jail_unknown_name_allowed_bootstrap);
ATF_TEST_CASE_BODY(authorize_destroy_jail_unknown_name_allowed_bootstrap) {
  auto e = env1000();
  auto l = fixedOwner(77, "web", 1000);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::DestroyJail, reqName("legacy-vm"), e, l)
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_create_jail_not_keyed_on_jail_name);
ATF_TEST_CASE_BODY(authorize_create_jail_not_keyed_on_jail_name) {
  // Distinct from destroy_jail: create_jail does NOT compare the new
  // jail's name against the registry (the name is brand new). The gate
  // is the path-prefix check below; this test pins the "no name gate"
  // shape so a future refactor can't accidentally reintroduce one.
  auto e = env1000();
  auto l = fixedOwner(77, "web", 1001);   // someone else owns "web"
  Request rq;
  rq.jailName = "brand-new";
  rq.path     = e.pathPrefix + "/brand-new";   // inside the caller's prefix
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::CreateJail, rq, e, l)
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_null_callbacks_in_lookup_allow);
ATF_TEST_CASE_BODY(authorize_null_callbacks_in_lookup_allow) {
  // If a daemon hands us an OwnerLookup with no callbacks installed
  // (e.g. registry not yet initialized), every probe is treated as
  // unknown -> Allow. Mirrors nullLookup() semantics for safety.
  auto e = env1000();
  OwnerLookup empty;   // all std::function members default-constructed (null)
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::SignalJail, reqJid(77), e, empty)
              == Decision::Allow);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::DestroyJail, reqName("web"), e, empty)
              == Decision::Allow);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::MountNullfs, reqPath("/jails/web/etc"),
                                          e, empty) == Decision::Allow);
}

// --- 1.1.14: path-scoped gating ---

ATF_TEST_CASE_WITHOUT_HEAD(authorize_path_own_target_allowed);
ATF_TEST_CASE_BODY(authorize_path_own_target_allowed) {
  auto e = env1000();
  auto l = fixedOwner(77, "web", 1000, "/jails/web");
  for (Verb v : {Verb::MountNullfs, Verb::UnmountNullfs,
                 Verb::ApplyDevfsRuleset, Verb::AddDevfsUnhideRule}) {
    ATF_REQUIRE(PrivOpsAuthzPure::authorize(v, reqPath("/jails/web/dev"), e, l)
                == Decision::Allow);
    ATF_REQUIRE(PrivOpsAuthzPure::authorize(v, reqPath("/jails/web/etc/rc.conf"), e, l)
                == Decision::Allow);
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_path_foreign_target_denied);
ATF_TEST_CASE_BODY(authorize_path_foreign_target_denied) {
  // Hostile operator (uid 1000) names a path inside a jail owned by 1001.
  auto e = env1000();
  auto l = fixedOwner(77, "web", /*ownerUid=*/1001, "/jails/web");
  for (Verb v : {Verb::MountNullfs, Verb::UnmountNullfs,
                 Verb::ApplyDevfsRuleset, Verb::AddDevfsUnhideRule}) {
    ATF_REQUIRE(PrivOpsAuthzPure::authorize(v, reqPath("/jails/web/dev"), e, l)
                == Decision::DenyForeignPath);
    ATF_REQUIRE(PrivOpsAuthzPure::authorize(v, reqPath("/jails/web"), e, l)
                == Decision::DenyForeignPath);
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_path_unknown_target_allowed_bootstrap);
ATF_TEST_CASE_BODY(authorize_path_unknown_target_allowed_bootstrap) {
  // Path outside every registered jail — pre-1.1.14 mount points and
  // jails created before 1.1.13 fall here. Allow with audit.
  auto e = env1000();
  auto l = fixedOwner(77, "web", 1001, "/jails/web");
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::MountNullfs,
                                          reqPath("/jails/legacy/etc"), e, l)
              == Decision::Allow);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::ApplyDevfsRuleset,
                                          reqPath("/zpool/somewhere/dev"), e, l)
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_path_substring_neighbor_not_owned);
ATF_TEST_CASE_BODY(authorize_path_substring_neighbor_not_owned) {
  // The fixedOwner lookup is slash-anchored: /jails/web does NOT own
  // /jails/webhook. So a verb targeting the neighbor falls through to
  // bootstrap-Allow, not DenyForeignPath — fewer false denies, same
  // safety (it's not our jail, so whoever does own it is responsible).
  auto e = env1000();
  auto l = fixedOwner(77, "web", 1001, "/jails/web");
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::MountNullfs,
                                          reqPath("/jails/webhook/etc"), e, l)
              == Decision::Allow);
}

// --- 1.1.15: pathOwned + create_jail path-prefix gate ---

ATF_TEST_CASE_WITHOUT_HEAD(path_owned_prefix_and_descendants);
ATF_TEST_CASE_BODY(path_owned_prefix_and_descendants) {
  const std::string p = "/jails-tenants/1000";
  ATF_REQUIRE(pathOwned(p, p));                              // prefix root
  ATF_REQUIRE(pathOwned(p + "/web", p));                     // child
  ATF_REQUIRE(pathOwned(p + "/web/etc", p));                 // grandchild
}

ATF_TEST_CASE_WITHOUT_HEAD(path_owned_rejects_foreign_and_substring);
ATF_TEST_CASE_BODY(path_owned_rejects_foreign_and_substring) {
  const std::string p = "/jails-tenants/1000";
  ATF_REQUIRE(!pathOwned("/jails-tenants/1001/web", p));     // other uid
  ATF_REQUIRE(!pathOwned("/elsewhere/1000", p));             // other master
  // Slash-anchored: a numerically-prefixed neighbor must not pass
  // (/...1000 must not own /...10001).
  ATF_REQUIRE(!pathOwned("/jails-tenants/10001", p));
  ATF_REQUIRE(!pathOwned("/jails-tenants/1000extra", p));
}

ATF_TEST_CASE_WITHOUT_HEAD(path_owned_empty_prefix_allows_all);
ATF_TEST_CASE_BODY(path_owned_empty_prefix_allows_all) {
  // No per-user path split configured -> nothing to gate.
  ATF_REQUIRE(pathOwned("/anything/at/all", ""));
  ATF_REQUIRE(pathOwned("", ""));
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_create_jail_inside_own_prefix);
ATF_TEST_CASE_BODY(authorize_create_jail_inside_own_prefix) {
  auto e = env1000();
  OwnerLookup empty;   // create_jail doesn't consult the registry
  Request rq;
  rq.jailName = "web";
  rq.path     = "/jails-tenants/1000/web";
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::CreateJail, rq, e, empty)
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_create_jail_outside_prefix_denied);
ATF_TEST_CASE_BODY(authorize_create_jail_outside_prefix_denied) {
  auto e = env1000();
  OwnerLookup empty;
  Request rq;
  rq.jailName = "evil";
  rq.path     = "/jails-tenants/1001/evil";   // another operator's territory
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::CreateJail, rq, e, empty)
              == Decision::DenyForeignCreatePath);

  rq.path = "/etc/passwd";                    // anywhere outside the prefix
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::CreateJail, rq, e, empty)
              == Decision::DenyForeignCreatePath);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_create_jail_unconfigured_split_allows);
ATF_TEST_CASE_BODY(authorize_create_jail_unconfigured_split_allows) {
  // Deployment didn't set pathMasterPrefix -> env.pathPrefix is empty
  // -> nothing to gate, allow any path. Preserves the upgrade shape.
  PerUserEnvPure::Env e = env1000();
  e.pathPrefix = "";
  Request rq;
  rq.jailName = "anywhere";
  rq.path     = "/zpool/jails/anywhere";
  OwnerLookup empty;
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::CreateJail, rq, e, empty)
              == Decision::Allow);
}

// --- 1.1.17: mount_nullfs source / configure_iface / reclaim gates ---

namespace {
Request reqMount(std::string target, std::string source) {
  Request r; r.path = std::move(target); r.source = std::move(source); return r;
}
} // namespace

ATF_TEST_CASE_WITHOUT_HEAD(mount_source_own_and_host_allowed);
ATF_TEST_CASE_BODY(mount_source_own_and_host_allowed) {
  auto e = env1000();
  // owner of jid/name/path 1000; target path owned -> Allow, then source.
  auto l = fixedOwner(77, "web", 1000, "/jails-tenants/1000/web");
  // own source (inside caller prefix)
  ATF_REQUIRE(authorize(Verb::MountNullfs,
                reqMount("/jails-tenants/1000/web/data", "/jails-tenants/1000/share"),
                e, l) == Decision::Allow);
  // host path outside the tenant root — privops is single-trust-domain for host
  ATF_REQUIRE(authorize(Verb::MountNullfs,
                reqMount("/jails-tenants/1000/web/data", "/etc"), e, l) == Decision::Allow);
  // GUI runtime socket — not under any tenant prefix
  ATF_REQUIRE(authorize(Verb::MountNullfs,
                reqMount("/jails-tenants/1000/web/data", "/tmp/.X11-unix"), e, l)
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(mount_source_foreign_tenant_denied);
ATF_TEST_CASE_BODY(mount_source_foreign_tenant_denied) {
  auto e = env1000();
  auto l = fixedOwner(77, "web", 1000, "/jails-tenants/1000/web");
  // source reaches into uid 1001's prefix -> deny
  ATF_REQUIRE(authorize(Verb::MountNullfs,
                reqMount("/jails-tenants/1000/web/x", "/jails-tenants/1001/secret"),
                e, l) == Decision::DenyForeignSource);
  // foreign TARGET still takes precedence over the source check
  auto l2 = fixedOwner(77, "web", 1001, "/jails-tenants/1001/web");
  ATF_REQUIRE(authorize(Verb::MountNullfs,
                reqMount("/jails-tenants/1001/web/x", "/etc"), e, l2)
              == Decision::DenyForeignPath);
}

ATF_TEST_CASE_WITHOUT_HEAD(mount_source_unconfigured_allows);
ATF_TEST_CASE_BODY(mount_source_unconfigured_allows) {
  // No pathMasterPrefix -> source gate is opt-in, off.
  PerUserEnvPure::Env e; e.uid = 1000;
  ATF_REQUIRE(authorize(Verb::MountNullfs,
                reqMount("/anything", "/jails-tenants/1001/secret"), e,
                PrivOpsAuthzPure::nullLookup())
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(configure_iface_jid_scoped);
ATF_TEST_CASE_BODY(configure_iface_jid_scoped) {
  auto e = env1000();
  ATF_REQUIRE(authorize(Verb::ConfigureIface, reqJid(77), e, fixedOwner(77,"web",1000))
              == Decision::Allow);                              // own jid
  ATF_REQUIRE(authorize(Verb::ConfigureIface, reqJid(77), e, fixedOwner(77,"web",1001))
              == Decision::DenyForeignJid);                     // foreign jid
  ATF_REQUIRE(authorize(Verb::ConfigureIface, reqJid(999), e, fixedOwner(77,"web",1000))
              == Decision::Allow);                              // unknown -> bootstrap
}

ATF_TEST_CASE_WITHOUT_HEAD(reclaim_iface_name_scoped);
ATF_TEST_CASE_BODY(reclaim_iface_name_scoped) {
  auto e = env1000();
  ATF_REQUIRE(authorize(Verb::ReclaimIfaceFromVnet, reqName("web"), e, fixedOwner(77,"web",1000))
              == Decision::Allow);                              // own jail
  ATF_REQUIRE(authorize(Verb::ReclaimIfaceFromVnet, reqName("web"), e, fixedOwner(77,"web",1001))
              == Decision::DenyForeignJailName);                // foreign jail
  ATF_REQUIRE(authorize(Verb::ReclaimIfaceFromVnet, reqName("other"), e, fixedOwner(77,"web",1000))
              == Decision::Allow);                              // unknown -> bootstrap
}

ATF_TEST_CASE_WITHOUT_HEAD(host_global_verbs_still_allowed);
ATF_TEST_CASE_BODY(host_global_verbs_still_allowed) {
  auto e = env1000();
  auto foreign = fixedOwner(77, "web", 1001);   // someone else owns everything
  // genuinely host-global verbs are unaffected by the 1.1.17 tightening
  for (Verb v : {Verb::TeardownIface, Verb::AddPfRule, Verb::AddIpfwRule,
                 Verb::SetIfaceUp, Verb::BridgeAddMember, Verb::CreateEpair}) {
    ATF_REQUIRE(authorize(v, Request{}, e, foreign) == Decision::Allow);
  }
}

// --- decisionReason ---

ATF_TEST_CASE_WITHOUT_HEAD(decision_reason_non_empty);
ATF_TEST_CASE_BODY(decision_reason_non_empty) {
  ATF_REQUIRE(std::string(decisionReason(Decision::Allow)) == "allow");
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignDataset)).empty());
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignLoginclass)).empty());
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignJid)).empty());
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignJailName)).empty());
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignPath)).empty());
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignCreatePath)).empty());
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignSource)).empty());
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, dataset_owned_prefix_and_descendants);
  ATF_ADD_TEST_CASE(tcs, dataset_owned_rejects_foreign_and_substring);
  ATF_ADD_TEST_CASE(tcs, dataset_owned_empty_prefix_allows_all);
  ATF_ADD_TEST_CASE(tcs, authorize_attach_zfs_own_dataset);
  ATF_ADD_TEST_CASE(tcs, authorize_attach_zfs_foreign_dataset_denied);
  ATF_ADD_TEST_CASE(tcs, authorize_dataset_unconfigured_split_allows);
  ATF_ADD_TEST_CASE(tcs, authorize_loginclass_own_umbrella);
  ATF_ADD_TEST_CASE(tcs, authorize_loginclass_foreign_denied);
  ATF_ADD_TEST_CASE(tcs, authorize_loginclass_empty_fails_closed);
  ATF_ADD_TEST_CASE(tcs, authorize_host_global_verbs_allowed);
  ATF_ADD_TEST_CASE(tcs, authorize_jid_scoped_under_null_lookup_allows);
  ATF_ADD_TEST_CASE(tcs, authorize_jid_unknown_target_allowed_bootstrap);
  ATF_ADD_TEST_CASE(tcs, authorize_jid_own_target_allowed);
  ATF_ADD_TEST_CASE(tcs, authorize_jid_foreign_owner_denied);
  ATF_ADD_TEST_CASE(tcs, authorize_destroy_jail_own_name_allowed);
  ATF_ADD_TEST_CASE(tcs, authorize_destroy_jail_foreign_name_denied);
  ATF_ADD_TEST_CASE(tcs, authorize_destroy_jail_unknown_name_allowed_bootstrap);
  ATF_ADD_TEST_CASE(tcs, authorize_create_jail_not_keyed_on_jail_name);
  ATF_ADD_TEST_CASE(tcs, authorize_null_callbacks_in_lookup_allow);
  ATF_ADD_TEST_CASE(tcs, authorize_path_own_target_allowed);
  ATF_ADD_TEST_CASE(tcs, authorize_path_foreign_target_denied);
  ATF_ADD_TEST_CASE(tcs, authorize_path_unknown_target_allowed_bootstrap);
  ATF_ADD_TEST_CASE(tcs, authorize_path_substring_neighbor_not_owned);
  ATF_ADD_TEST_CASE(tcs, path_owned_prefix_and_descendants);
  ATF_ADD_TEST_CASE(tcs, path_owned_rejects_foreign_and_substring);
  ATF_ADD_TEST_CASE(tcs, path_owned_empty_prefix_allows_all);
  ATF_ADD_TEST_CASE(tcs, authorize_create_jail_inside_own_prefix);
  ATF_ADD_TEST_CASE(tcs, authorize_create_jail_outside_prefix_denied);
  ATF_ADD_TEST_CASE(tcs, authorize_create_jail_unconfigured_split_allows);
  ATF_ADD_TEST_CASE(tcs, mount_source_own_and_host_allowed);
  ATF_ADD_TEST_CASE(tcs, mount_source_foreign_tenant_denied);
  ATF_ADD_TEST_CASE(tcs, mount_source_unconfigured_allows);
  ATF_ADD_TEST_CASE(tcs, configure_iface_jid_scoped);
  ATF_ADD_TEST_CASE(tcs, reclaim_iface_name_scoped);
  ATF_ADD_TEST_CASE(tcs, host_global_verbs_still_allowed);
  ATF_ADD_TEST_CASE(tcs, decision_reason_non_empty);
}
