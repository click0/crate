// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "sandbox_pure.h"

#include <atf-c++.hpp>

#include <set>
#include <string>

using SandboxPure::FdRole;
using SandboxPure::describe;
using SandboxPure::labelFor;
using SandboxPure::rightCountFor;

ATF_TEST_CASE_WITHOUT_HEAD(labels_are_distinct);
ATF_TEST_CASE_BODY(labels_are_distinct) {
  // Stable labels surface in startup logs; collisions would defeat
  // the purpose of the diagnostic. Every role must produce a unique,
  // non-empty label.
  std::set<std::string> seen;
  FdRole roles[] = {
    FdRole::Listener, FdRole::Connection,
    FdRole::LogWrite, FdRole::ConfigRead,
  };
  for (auto r : roles) {
    std::string lbl = labelFor(r);
    ATF_REQUIRE(!lbl.empty());
    ATF_REQUIRE(seen.insert(lbl).second);  // unique
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(labels_are_stable);
ATF_TEST_CASE_BODY(labels_are_stable) {
  // Pin the exact strings — operator-visible in logs, log scrapers
  // depend on them.
  ATF_REQUIRE_EQ(std::string(labelFor(FdRole::Listener)),    std::string("listener"));
  ATF_REQUIRE_EQ(std::string(labelFor(FdRole::Connection)),  std::string("connection"));
  ATF_REQUIRE_EQ(std::string(labelFor(FdRole::LogWrite)),    std::string("log-write"));
  ATF_REQUIRE_EQ(std::string(labelFor(FdRole::ConfigRead)),  std::string("config-read"));
}

ATF_TEST_CASE_WITHOUT_HEAD(right_counts_match_runtime);
ATF_TEST_CASE_BODY(right_counts_match_runtime) {
  // The counts here are the contract with daemon/sandbox.cpp's
  // apply(...) calls. If a maintainer adds a CAP_* there without
  // bumping the count here, this test fails — surfacing the drift.
  //
  //   Listener   -> 3   (CAP_ACCEPT, CAP_GETSOCKOPT, CAP_FSTAT)
  //   Connection -> 5   (CAP_RECV, CAP_SEND, CAP_SHUTDOWN,
  //                      CAP_GETSOCKOPT, CAP_FSTAT)
  //   LogWrite   -> 3   (CAP_WRITE, CAP_FSYNC, CAP_FSTAT)
  //   ConfigRead -> 2   (CAP_READ, CAP_FSTAT)
  ATF_REQUIRE_EQ(rightCountFor(FdRole::Listener),    3u);
  ATF_REQUIRE_EQ(rightCountFor(FdRole::Connection),  5u);
  ATF_REQUIRE_EQ(rightCountFor(FdRole::LogWrite),    3u);
  ATF_REQUIRE_EQ(rightCountFor(FdRole::ConfigRead),  2u);
}

ATF_TEST_CASE_WITHOUT_HEAD(right_counts_strictly_positive);
ATF_TEST_CASE_BODY(right_counts_strictly_positive) {
  // Every role limits to at least CAP_FSTAT (so libc's fstat-based
  // optimisations like fcntl-stdio buffering keep working). Zero
  // would mean the fd is unusable — definitely a bug.
  FdRole roles[] = {
    FdRole::Listener, FdRole::Connection,
    FdRole::LogWrite, FdRole::ConfigRead,
  };
  for (auto r : roles)
    ATF_REQUIRE(rightCountFor(r) > 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(connection_has_strictly_more_rights_than_listener);
ATF_TEST_CASE_BODY(connection_has_strictly_more_rights_than_listener) {
  // A listener can only accept; a connection has a richer set
  // (recv + send + shutdown + sockopt + fstat). If someone swaps
  // these mappings, this test catches it.
  ATF_REQUIRE(rightCountFor(FdRole::Connection)
              > rightCountFor(FdRole::Listener));
}

ATF_TEST_CASE_WITHOUT_HEAD(describe_format);
ATF_TEST_CASE_BODY(describe_format) {
  auto s = describe(7, FdRole::Listener);
  ATF_REQUIRE(s.find("sandbox:")  != std::string::npos);
  ATF_REQUIRE(s.find("fd 7")      != std::string::npos);
  ATF_REQUIRE(s.find("listener")  != std::string::npos);
  ATF_REQUIRE(s.find("3 rights")  != std::string::npos);

  // Negative fd values are still rendered (e.g. -1 from a failed
  // bind) — operators see "fd -1" instead of garbage.
  auto s2 = describe(-1, FdRole::Connection);
  ATF_REQUIRE(s2.find("fd -1")    != std::string::npos);
  ATF_REQUIRE(s2.find("connection") != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, labels_are_distinct);
  ATF_ADD_TEST_CASE(tcs, labels_are_stable);
  ATF_ADD_TEST_CASE(tcs, right_counts_match_runtime);
  ATF_ADD_TEST_CASE(tcs, right_counts_strictly_positive);
  ATF_ADD_TEST_CASE(tcs, connection_has_strictly_more_rights_than_listener);
  ATF_ADD_TEST_CASE(tcs, describe_format);
}
