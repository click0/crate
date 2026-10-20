// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "mac_pure.h"

#include <atf-c++.hpp>

using namespace MacPure;

ATF_TEST_CASE_WITHOUT_HEAD(format_and_split);
ATF_TEST_CASE_BODY(format_and_split) {
  ATF_REQUIRE_EQ(formatPortaclRule(0, "tcp", 80), std::string("uid:0:tcp:80"));
  auto v = splitPortaclRules(" uid:0:tcp:80, uid:0:udp:80 ,,gid:5:tcp:443,");
  ATF_REQUIRE_EQ(v.size(), 3u);
  ATF_REQUIRE_EQ(v[0], std::string("uid:0:tcp:80"));
  ATF_REQUIRE_EQ(v[1], std::string("uid:0:udp:80"));
  ATF_REQUIRE_EQ(v[2], std::string("gid:5:tcp:443"));
  ATF_REQUIRE(splitPortaclRules("").empty());
  ATF_REQUIRE(splitPortaclRules(" , ").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(merge_keeps_others_and_dedups);
ATF_TEST_CASE_BODY(merge_keeps_others_and_dedups) {
  // operator's own rule + another container's rule survive; ours are
  // appended once even if asked twice or already present
  std::string cur = "gid:80:tcp:443,uid:0:tcp:8080";
  auto merged = mergePortaclRules(cur, {"uid:0:tcp:80", "uid:0:udp:80", "uid:0:tcp:80", "uid:0:tcp:8080"});
  ATF_REQUIRE_EQ(merged, std::string("gid:80:tcp:443,uid:0:tcp:8080,uid:0:tcp:80,uid:0:udp:80"));
  // empty current -> just ours
  ATF_REQUIRE_EQ(mergePortaclRules("", {"uid:0:tcp:80"}), std::string("uid:0:tcp:80"));
  // nothing to add -> unchanged (normalised)
  ATF_REQUIRE_EQ(mergePortaclRules(" uid:0:tcp:80 ,", {}), std::string("uid:0:tcp:80"));
}

ATF_TEST_CASE_WITHOUT_HEAD(remove_takes_only_ours);
ATF_TEST_CASE_BODY(remove_takes_only_ours) {
  std::string cur = "gid:80:tcp:443,uid:0:tcp:80,uid:0:udp:80,uid:0:tcp:8080";
  ATF_REQUIRE_EQ(removePortaclRules(cur, {"uid:0:tcp:80", "uid:0:udp:80"}),
                 std::string("gid:80:tcp:443,uid:0:tcp:8080"));
  // removing what is not there is a no-op
  ATF_REQUIRE_EQ(removePortaclRules(cur, {"uid:0:tcp:1"}), cur);
  // removing everything -> empty value (sysctl accepts "")
  ATF_REQUIRE_EQ(removePortaclRules("uid:0:tcp:80", {"uid:0:tcp:80"}), std::string());
  // round trip: merge then remove restores the original list
  std::string orig = "gid:80:tcp:443";
  auto m = mergePortaclRules(orig, {"uid:0:tcp:80"});
  ATF_REQUIRE_EQ(removePortaclRules(m, {"uid:0:tcp:80"}), orig);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, format_and_split);
  ATF_ADD_TEST_CASE(tcs, merge_keeps_others_and_dedups);
  ATF_ADD_TEST_CASE(tcs, remove_takes_only_ours);
}
