// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "passwd_pure.h"

#include <atf-c++.hpp>

using namespace PasswdPure;

static const char kMaster[] =
  "# $FreeBSD$\n"
  "#\n"
  "root:$6$abc:0:0::0:0:Charlie &:/root:/bin/sh\n"
  "toor:*:0:0::0:0:Bourne-again Superuser:/root:\n"
  "daemon:*:1:1::0:0:Owner of many system processes:/root:/usr/sbin/nologin\n"
  "www:*:80:80::0:0:World Wide Web Owner:/nonexistent:/usr/sbin/nologin\n"
  "alice:$6$xyz:1001:1001:staff:0:0:Alice:/home/alice:/usr/local/bin/zsh\r\n"
  "broken:line:with:too:few\n"
  "bob:*:notanumber:1002::0:0::/home/bob:/bin/sh\n"
  "carol:*:1003:4294967296::0:0::/home/carol:/bin/sh\n";

static const char kGroup[] =
  "# comment\n"
  "wheel:*:0:root,alice\n"
  "daemon:*:1:\n"
  "operator:*:5:root\n"
  "staff:*:20:alice,bob\n"
  "video:*:44:alice\n"
  "bad:*:x:alice\n"
  "short:*:7\n"
  "dup:*:44:alice\n"
  "alice:*:1001:\n";

ATF_TEST_CASE_WITHOUT_HEAD(parse_master_line);
ATF_TEST_CASE_BODY(parse_master_line) {
  User u;
  ATF_REQUIRE(parseMasterPasswdLine("alice:$6$xyz:1001:1001:staff:0:0:Alice:/home/alice:/usr/local/bin/zsh", u));
  ATF_REQUIRE_EQ(u.name, std::string("alice"));
  ATF_REQUIRE_EQ(u.uid, 1001u);
  ATF_REQUIRE_EQ(u.gid, 1001u);
  ATF_REQUIRE_EQ(u.loginClass, std::string("staff"));
  ATF_REQUIRE_EQ(u.home, std::string("/home/alice"));
  ATF_REQUIRE_EQ(u.shell, std::string("/usr/local/bin/zsh"));
  // empty class / empty shell are legal
  ATF_REQUIRE(parseMasterPasswdLine("toor:*:0:0::0:0:Bourne-again Superuser:/root:", u));
  ATF_REQUIRE(u.loginClass.empty());
  ATF_REQUIRE(u.shell.empty());
  // rejected shapes
  ATF_REQUIRE(!parseMasterPasswdLine("# comment", u));
  ATF_REQUIRE(!parseMasterPasswdLine("", u));
  ATF_REQUIRE(!parseMasterPasswdLine("root:*:0:0:/root:/bin/sh", u));             // 6 fields
  ATF_REQUIRE(parseMasterPasswdLine("root:*:0:0::0:0:gecos:/root:/bin/sh", u));          // 10 ok
  ATF_REQUIRE(!parseMasterPasswdLine(":*:0:0::0:0::/root:/bin/sh", u));            // empty name
  ATF_REQUIRE(!parseMasterPasswdLine("bob:*:-1:0::0:0::/home/bob:/bin/sh", u));    // negative
  ATF_REQUIRE(!parseMasterPasswdLine("bob:*:1:4294967296::0:0::/home/bob:/bin/sh", u)); // > uint32
  ATF_REQUIRE(!parseMasterPasswdLine("bob:*:1:1::0:0::/home/bob:/bin/sh:extra", u)); // 11 fields
}

ATF_TEST_CASE_WITHOUT_HEAD(lookup_user_master_and_passwd_formats);
ATF_TEST_CASE_BODY(lookup_user_master_and_passwd_formats) {
  User u;
  ATF_REQUIRE(lookupUser(kMaster, "alice", u));
  ATF_REQUIRE_EQ(u.uid, 1001u);
  ATF_REQUIRE_EQ(u.loginClass, std::string("staff"));
  ATF_REQUIRE_EQ(u.shell, std::string("/usr/local/bin/zsh"));   // CRLF stripped
  ATF_REQUIRE(lookupUser(kMaster, "root", u));
  ATF_REQUIRE_EQ(u.uid, 0u);
  ATF_REQUIRE_EQ(u.home, std::string("/root"));
  // malformed entries never resolve, even when the name matches
  ATF_REQUIRE(!lookupUser(kMaster, "broken", u));
  ATF_REQUIRE(!lookupUser(kMaster, "bob", u));
  ATF_REQUIRE(!lookupUser(kMaster, "carol", u));
  ATF_REQUIRE(!lookupUser(kMaster, "nobody", u));
  ATF_REQUIRE(!lookupUser(kMaster, "", u));
  // a name that is a prefix/suffix of another is not a match
  ATF_REQUIRE(!lookupUser(kMaster, "alic", u));
  ATF_REQUIRE(!lookupUser(kMaster, "ww", u));
  // passwd(5) 7-field form
  const char *pw = "www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin\n";
  ATF_REQUIRE(lookupUser(pw, "www", u));
  ATF_REQUIRE_EQ(u.uid, 80u);
  ATF_REQUIRE_EQ(u.gid, 80u);
  ATF_REQUIRE(u.loginClass.empty());
  ATF_REQUIRE_EQ(u.home, std::string("/nonexistent"));
  ATF_REQUIRE_EQ(u.shell, std::string("/usr/sbin/nologin"));
}

ATF_TEST_CASE_WITHOUT_HEAD(supplementary_groups);
ATF_TEST_CASE_BODY(supplementary_groups) {
  auto g = supplementaryGroups(kGroup, "alice", 1001);
  // primary first, then wheel(0), staff(20), video(44); "dup" (44 again)
  // and alice's own group (1001 == primary) are not duplicated; "bad"
  // and "short" are skipped.
  ATF_REQUIRE_EQ(g.size(), 4u);
  ATF_REQUIRE_EQ(g[0], 1001u);
  ATF_REQUIRE_EQ(g[1], 0u);
  ATF_REQUIRE_EQ(g[2], 20u);
  ATF_REQUIRE_EQ(g[3], 44u);
  // a user in no group gets just the primary
  auto n = supplementaryGroups(kGroup, "nobody", 65534);
  ATF_REQUIRE_EQ(n.size(), 1u);
  ATF_REQUIRE_EQ(n[0], 65534u);
  // "ali" must not match "alice" as a member
  auto p = supplementaryGroups(kGroup, "ali", 7);
  ATF_REQUIRE_EQ(p.size(), 1u);
  // cap honoured (primary + 1)
  auto c = supplementaryGroups(kGroup, "alice", 1001, 2);
  ATF_REQUIRE_EQ(c.size(), 2u);
  ATF_REQUIRE_EQ(c[1], 0u);
  // empty content / empty user
  ATF_REQUIRE_EQ(supplementaryGroups("", "alice", 5).size(), 1u);
  ATF_REQUIRE_EQ(supplementaryGroups(kGroup, "", 5).size(), 1u);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, parse_master_line);
  ATF_ADD_TEST_CASE(tcs, lookup_user_master_and_passwd_formats);
  ATF_ADD_TEST_CASE(tcs, supplementary_groups);
}
