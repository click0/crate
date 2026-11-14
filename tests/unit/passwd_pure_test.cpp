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

// 1.1.77: the only environment that crosses into a jail.
ATF_TEST_CASE_WITHOUT_HEAD(jail_exec_env);
ATF_TEST_CASE_BODY(jail_exec_env) {
  auto e = PasswdPure::jailExecEnv("alice", "/home/alice", "/bin/csh", "xterm");
  ATF_REQUIRE_EQ(e.size(), 6u);
  ATF_REQUIRE_EQ(e[0], std::string("PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"));
  ATF_REQUIRE_EQ(e[1], std::string("HOME=/home/alice"));
  ATF_REQUIRE_EQ(e[2], std::string("SHELL=/bin/csh"));
  ATF_REQUIRE_EQ(e[3], std::string("USER=alice"));
  ATF_REQUIRE_EQ(e[4], std::string("LOGNAME=alice"));
  ATF_REQUIRE_EQ(e[5], std::string("TERM=xterm"));
  auto r = PasswdPure::jailExecEnv("root", "", "", "");
  ATF_REQUIRE_EQ(r.size(), 5u);                     // no TERM
  ATF_REQUIRE_EQ(r[1], std::string("HOME=/"));
  ATF_REQUIRE_EQ(r[2], std::string("SHELL=/bin/sh"));
  // LANG: a plain locale name is passed, anything else dropped
  auto l = PasswdPure::jailExecEnv("alice", "/home/alice", "/bin/sh", "", "uk_UA.UTF-8");
  ATF_REQUIRE_EQ(l.size(), 6u);
  ATF_REQUIRE_EQ(l[5], std::string("LANG=uk_UA.UTF-8"));
  ATF_REQUIRE_EQ(PasswdPure::jailExecEnv("a", "/", "/bin/sh", "", "ca_ES@valencia").back(),
                 std::string("LANG=ca_ES@valencia"));
  ATF_REQUIRE_EQ(PasswdPure::jailExecEnv("a", "/", "/bin/sh", "", "C\nX=1").size(), 5u);
  ATF_REQUIRE_EQ(PasswdPure::jailExecEnv("a", "/", "/bin/sh", "", "en US").size(), 5u);
  ATF_REQUIRE_EQ(PasswdPure::jailExecEnv("a", "/", "/bin/sh", "", std::string(65, 'a')).size(), 5u);
}

// 1.1.78: the jail's display variables for what JailExec runs (services,
// hooks): four fixed names, each value checked for shape.
ATF_TEST_CASE_WITHOUT_HEAD(jail_display_env);
ATF_TEST_CASE_BODY(jail_display_env) {
  using PasswdPure::JailDisplayEnv;
  JailDisplayEnv d;
  ATF_REQUIRE(d.empty());
  ATF_REQUIRE(PasswdPure::validateJailDisplayEnv(d).empty());
  // none set: the environment is what it was
  ATF_REQUIRE_EQ(PasswdPure::jailExecEnv("a", "/", "/bin/sh", "", "", d).size(), 5u);

  // the names map to the fields, nothing else does
  *PasswdPure::jailDisplayField(d, "DISPLAY") = ":10";
  *PasswdPure::jailDisplayField(d, "XAUTHORITY") = "/var/run/crate-Xauthority";
  *PasswdPure::jailDisplayField(d, "WAYLAND_DISPLAY") = "wayland-1";
  *PasswdPure::jailDisplayField(d, "XDG_RUNTIME_DIR") = "/tmp/wayland";
  ATF_REQUIRE(PasswdPure::jailDisplayField(d, "CRATE") == nullptr);
  ATF_REQUIRE(PasswdPure::jailDisplayField(d, "LD_PRELOAD") == nullptr);
  ATF_REQUIRE(PasswdPure::jailDisplayField(d, "DBUS_SESSION_BUS_ADDRESS") == nullptr);
  ATF_REQUIRE(PasswdPure::jailDisplayField(d, "display") == nullptr);
  ATF_REQUIRE(!d.empty());
  ATF_REQUIRE(PasswdPure::validateJailDisplayEnv(d).empty());

  auto e = PasswdPure::jailExecEnv("alice", "/home/alice", "/bin/sh", "xterm", "uk_UA.UTF-8", d);
  ATF_REQUIRE_EQ(e.size(), 11u);
  ATF_REQUIRE_EQ(e[7], std::string("DISPLAY=:10"));
  ATF_REQUIRE_EQ(e[8], std::string("XAUTHORITY=/var/run/crate-Xauthority"));
  ATF_REQUIRE_EQ(e[9], std::string("WAYLAND_DISPLAY=wayland-1"));
  ATF_REQUIRE_EQ(e[10], std::string("XDG_RUNTIME_DIR=/tmp/wayland"));

  // other DISPLAY forms the shared mode passes on
  for (const char *ok : {":0", ":0.0", "unix:1", "localhost:10.0", "host-1.example.org:0"}) {
    JailDisplayEnv x; x.display = ok;
    ATF_REQUIRE(PasswdPure::validateJailDisplayEnv(x).empty());
  }
  // malformed values: refused by the validator, left out of the env
  auto bad = [](const JailDisplayEnv &x, const char *field) {
    const auto err = PasswdPure::validateJailDisplayEnv(x);
    ATF_REQUIRE(err.find(field) == 0);
    ATF_REQUIRE_EQ(PasswdPure::jailExecEnv("a", "/", "/bin/sh", "", "", x).size(), 5u);
  };
  JailDisplayEnv x;
  x = JailDisplayEnv(); x.display = ":0\nLD_PRELOAD=/tmp/x.so";         bad(x, "display");
  x = JailDisplayEnv(); x.display = ":0 x";                             bad(x, "display");
  x = JailDisplayEnv(); x.display = "$(id)";                            bad(x, "display");
  x = JailDisplayEnv(); x.display = std::string(65, '0');               bad(x, "display");
  x = JailDisplayEnv(); x.waylandDisplay = "../wayland-0";              bad(x, "wayland_display");
  x = JailDisplayEnv(); x.waylandDisplay = "/run/user/0/wayland-0";     bad(x, "wayland_display");
  x = JailDisplayEnv(); x.waylandDisplay = "..";                        bad(x, "wayland_display");
  x = JailDisplayEnv(); x.xauthority = "root/.Xauthority";              bad(x, "xauthority");
  x = JailDisplayEnv(); x.xauthority = "/root/../etc/passwd";           bad(x, "xauthority");
  x = JailDisplayEnv(); x.xauthority = "/root/.Xauthority;rm";          bad(x, "xauthority");
  x = JailDisplayEnv(); x.xauthority = "/" + std::string(255, 'a');     bad(x, "xauthority");
  x = JailDisplayEnv(); x.xdgRuntimeDir = "/tmp/way land";              bad(x, "xdg_runtime_dir");
  x = JailDisplayEnv(); x.xdgRuntimeDir = "/tmp/..";                    bad(x, "xdg_runtime_dir");
  // a name with dots that is not ".." is a name
  x = JailDisplayEnv(); x.xauthority = "/home/a/..hidden/.Xauthority";
  ATF_REQUIRE(PasswdPure::validateJailDisplayEnv(x).empty());

  ATF_REQUIRE(PasswdPure::validLocaleName("C"));
  ATF_REQUIRE(PasswdPure::validLocaleName("uk_UA.UTF-8"));
  ATF_REQUIRE(!PasswdPure::validLocaleName(""));
  ATF_REQUIRE(!PasswdPure::validLocaleName("en US"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, parse_master_line);
  ATF_ADD_TEST_CASE(tcs, lookup_user_master_and_passwd_formats);
  ATF_ADD_TEST_CASE(tcs, supplementary_groups);
  ATF_ADD_TEST_CASE(tcs, jail_exec_env);
  ATF_ADD_TEST_CASE(tcs, jail_display_env);
}
