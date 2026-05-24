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

ATF_TEST_CASE_WITHOUT_HEAD(authorize_jid_scoped_verbs_not_yet_gated);
ATF_TEST_CASE_BODY(authorize_jid_scoped_verbs_not_yet_gated) {
  // jid-scoped verbs have no request-carried owner today; they are
  // deferred (still host-wide) and must not be denied here, or
  // legitimate rootless operations would break.
  auto e = env1000();
  ATF_REQUIRE(authorize(Verb::SetRctl, "", "", e)       == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::SignalJail, "", "", e)    == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::SetJailCpuset, "", "", e) == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::CreateJail, "", "", e)    == Decision::Allow);
  ATF_REQUIRE(authorize(Verb::QueryJailRctl, "", "", e) == Decision::Allow);
}

// --- decisionReason ---

ATF_TEST_CASE_WITHOUT_HEAD(decision_reason_non_empty);
ATF_TEST_CASE_BODY(decision_reason_non_empty) {
  ATF_REQUIRE(std::string(decisionReason(Decision::Allow)) == "allow");
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignDataset)).empty());
  ATF_REQUIRE(!std::string(decisionReason(Decision::DenyForeignLoginclass)).empty());
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
  ATF_ADD_TEST_CASE(tcs, authorize_jid_scoped_verbs_not_yet_gated);
  ATF_ADD_TEST_CASE(tcs, decision_reason_non_empty);
}
