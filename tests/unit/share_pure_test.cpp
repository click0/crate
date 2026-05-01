// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "share_pure.h"

#include <atf-c++.hpp>

#include <string>

using SharePure::FileShareInputs;
using SharePure::FileStrategy;
using SharePure::chooseFileStrategy;
using SharePure::strategyName;

ATF_TEST_CASE_WITHOUT_HEAD(neither_side_exists_is_error);
ATF_TEST_CASE_BODY(neither_side_exists_is_error) {
  FileShareInputs in{false, false, true};
  ATF_REQUIRE(chooseFileStrategy(in) == FileStrategy::Error);
  // sameDevice value irrelevant when both missing
  in.sameDevice = false;
  ATF_REQUIRE(chooseFileStrategy(in) == FileStrategy::Error);
}

ATF_TEST_CASE_WITHOUT_HEAD(both_exist_same_device_replaces_via_hardlink);
ATF_TEST_CASE_BODY(both_exist_same_device_replaces_via_hardlink) {
  FileShareInputs in{true, true, true};
  ATF_REQUIRE(chooseFileStrategy(in) == FileStrategy::HardLinkHostToJail);
}

ATF_TEST_CASE_WITHOUT_HEAD(both_exist_cross_device_uses_nullfs_bind);
ATF_TEST_CASE_BODY(both_exist_cross_device_uses_nullfs_bind) {
  FileShareInputs in{true, true, false};
  ATF_REQUIRE(chooseFileStrategy(in) == FileStrategy::NullfsBindHostToJail);
}

ATF_TEST_CASE_WITHOUT_HEAD(host_only_same_device_hardlinks_into_jail);
ATF_TEST_CASE_BODY(host_only_same_device_hardlinks_into_jail) {
  FileShareInputs in{true, false, true};
  ATF_REQUIRE(chooseFileStrategy(in) == FileStrategy::HardLinkHostToJailNew);
}

ATF_TEST_CASE_WITHOUT_HEAD(host_only_cross_device_falls_back_to_bind);
ATF_TEST_CASE_BODY(host_only_cross_device_falls_back_to_bind) {
  FileShareInputs in{true, false, false};
  ATF_REQUIRE(chooseFileStrategy(in) == FileStrategy::NullfsBindHostToJail);
}

ATF_TEST_CASE_WITHOUT_HEAD(jail_only_same_device_hardlinks_outward);
ATF_TEST_CASE_BODY(jail_only_same_device_hardlinks_outward) {
  FileShareInputs in{false, true, true};
  ATF_REQUIRE(chooseFileStrategy(in) == FileStrategy::HardLinkJailToHost);
}

ATF_TEST_CASE_WITHOUT_HEAD(jail_only_cross_device_copies_then_binds);
ATF_TEST_CASE_BODY(jail_only_cross_device_copies_then_binds) {
  FileShareInputs in{false, true, false};
  ATF_REQUIRE(chooseFileStrategy(in) == FileStrategy::CopyJailToHostThenBind);
}

ATF_TEST_CASE_WITHOUT_HEAD(strategy_names_are_distinct_and_stable);
ATF_TEST_CASE_BODY(strategy_names_are_distinct_and_stable) {
  // Each strategy must have a non-empty diagnostic name, all unique.
  const FileStrategy all[] = {
    FileStrategy::HardLinkHostToJail,
    FileStrategy::HardLinkHostToJailNew,
    FileStrategy::HardLinkJailToHost,
    FileStrategy::NullfsBindHostToJail,
    FileStrategy::CopyJailToHostThenBind,
    FileStrategy::Error,
  };
  std::string seen[6];
  for (size_t i = 0; i < 6; i++) {
    seen[i] = strategyName(all[i]);
    ATF_REQUIRE(!seen[i].empty());
    for (size_t j = 0; j < i; j++)
      ATF_REQUIRE(seen[i] != seen[j]);
  }
  // Spot-check a couple of stable names that callers may rely on.
  ATF_REQUIRE_EQ(std::string(strategyName(FileStrategy::NullfsBindHostToJail)),
                 "nullfs-bind-host-to-jail");
  ATF_REQUIRE_EQ(std::string(strategyName(FileStrategy::Error)), "error");
}

// Coverage matrix: every (hostExists, jailExists, sameDevice) triple maps
// to exactly one strategy and the mapping is total.
ATF_TEST_CASE_WITHOUT_HEAD(decision_table_is_total);
ATF_TEST_CASE_BODY(decision_table_is_total) {
  for (int h = 0; h < 2; h++)
    for (int j = 0; j < 2; j++)
      for (int s = 0; s < 2; s++) {
        FileShareInputs in{(bool)h, (bool)j, (bool)s};
        FileStrategy got = chooseFileStrategy(in);
        // An exhaustive switch with no `default` would force an unhandled
        // return; instead just assert each result is one of the known
        // enumerators.
        bool ok = got == FileStrategy::HardLinkHostToJail
               || got == FileStrategy::HardLinkHostToJailNew
               || got == FileStrategy::HardLinkJailToHost
               || got == FileStrategy::NullfsBindHostToJail
               || got == FileStrategy::CopyJailToHostThenBind
               || got == FileStrategy::Error;
        ATF_REQUIRE(ok);
      }
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, neither_side_exists_is_error);
  ATF_ADD_TEST_CASE(tcs, both_exist_same_device_replaces_via_hardlink);
  ATF_ADD_TEST_CASE(tcs, both_exist_cross_device_uses_nullfs_bind);
  ATF_ADD_TEST_CASE(tcs, host_only_same_device_hardlinks_into_jail);
  ATF_ADD_TEST_CASE(tcs, host_only_cross_device_falls_back_to_bind);
  ATF_ADD_TEST_CASE(tcs, jail_only_same_device_hardlinks_outward);
  ATF_ADD_TEST_CASE(tcs, jail_only_cross_device_copies_then_binds);
  ATF_ADD_TEST_CASE(tcs, strategy_names_are_distinct_and_stable);
  ATF_ADD_TEST_CASE(tcs, decision_table_is_total);
}
