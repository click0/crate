// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_authz_pure.h"

#include <atf-c++.hpp>

#include <string>

using PrivOpsAuthzPure::Decision;
using PrivOpsAuthzPure::authorize;
using PrivOpsAuthzPure::datasetOwned;
using PrivOpsAuthzPure::decisionReason;
using PrivOpsPure::Verb;

namespace {

// An Env scoped to uid 1000 with a per-user ZFS split configured.
PerUserEnvPure::Env env1000() {
  PerUserEnvPure::Env e;
  e.uid        = 1000;
  e.zfsPrefix  = "zroot/crate-tenants/1000";
  e.loginclass = "crate-1000";
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
  auto e = env1000();
  ATF_REQUIRE(authorize(Verb::SetRctl,        "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::ClearRctl,      "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::SignalJail,     "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::SetJailCpuset,  "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::QueryJailRctl,  "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::DestroyJail,    "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::CreateJail,     "", "", e) == Decision::Allow);
}

// --- 1.1.13: jid/name-scoped gating via OwnerLookup ---

namespace {

using PrivOpsAuthzPure::Owner;
using PrivOpsAuthzPure::OwnerLookup;
using PrivOpsAuthzPure::Request;

// Lookup that knows exactly one (jid, name) -> uid mapping. Useful for
// driving the gate without pulling in the impure registry class.
OwnerLookup fixedOwner(unsigned ownedJid, const std::string &ownedName,
                       uint32_t ownerUid) {
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
  return l;
}

Request reqJid(unsigned j) { Request r; r.jid = j; return r; }
Request reqName(std::string n) { Request r; r.jailName = std::move(n); return r; }

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

ATF_TEST_CASE_WITHOUT_HEAD(authorize_create_jail_never_gated_here);
ATF_TEST_CASE_BODY(authorize_create_jail_never_gated_here) {
  // The name is brand new (it would be the *future* registry entry) so
  // there's nothing to compare against. Path-prefix validation for
  // create_jail is the open follow-up and lives outside this module.
  auto e = env1000();
  auto l = fixedOwner(77, "web", 1001);   // someone else owns "web"
  // create_jail still passes here; if the operator tries to create a
  // SECOND jail under the existing name, the kernel will refuse it.
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::CreateJail, reqName("brand-new"), e, l)
              == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authorize_null_callbacks_in_lookup_allow);
ATF_TEST_CASE_BODY(authorize_null_callbacks_in_lookup_allow) {
  // If a daemon hands us an OwnerLookup with no callbacks installed
  // (e.g. registry not yet initialized), every probe is treated as
  // unknown -> Allow. Mirrors nullLookup() semantics for safety.
  auto e = env1000();
  OwnerLookup empty;   // both std::function members default-constructed (null)
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::SignalJail, reqJid(77), e, empty)
              == Decision::Allow);
  ATF_REQUIRE(PrivOpsAuthzPure::authorize(Verb::DestroyJail, reqName("web"), e, empty)
              == Decision::Allow);
}

// --- decisionReason ---

ATF_TEST_CASE_WITHOUT_HEAD(decision_reason_non_empty);
ATF_TEST_CASE_BODY(decision_reason_non_empty) {
  ATF_REQUIRE(std::string(decisionReason(Decision::Allow)) == "allow");
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignDataset)).empty());
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignLoginclass)).empty());
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignJid)).empty());
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignJailName)).empty());
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
  ATF_ADD_TEST_CASE(tcs, authorize_create_jail_never_gated_here);
  ATF_ADD_TEST_CASE(tcs, authorize_null_callbacks_in_lookup_allow);
  ATF_ADD_TEST_CASE(tcs, decision_reason_non_empty);
}
