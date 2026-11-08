// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.59: per-application profiles (`crate run <name>`) — pure rules.

#include "profile_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using namespace ProfilePure;

ATF_TEST_CASE_WITHOUT_HEAD(profile_names);
ATF_TEST_CASE_BODY(profile_names) {
  for (const char *ok : {"firefox", "firefox-gpu", "my.app", "a", "x_1", "chromium.privacy"})
    if (!validateProfileName(ok).empty()) ATF_FAIL(std::string(ok) + " should be a valid profile name");
  for (const char *bad : {"", "a/b", "-x", ".x", "..", "x.local", "a b", "chromium+tor",
                          "../firefox", "firefox.yml/"})
    if (validateProfileName(bad).empty()) ATF_FAIL(std::string("'") + bad + "' should be rejected");
  // 'local' alone and 'x.localhost' are fine: only the '.local' suffix is reserved
  ATF_REQUIRE_EQ(validateProfileName("local"), "");
  ATF_REQUIRE_EQ(validateProfileName("x.localhost"), "");
  ATF_REQUIRE(validateProfileName(std::string(129, 'a')).size() > 0);
  ATF_REQUIRE(validateProfileName("x.local").find(".local") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(search_paths_and_layout);
ATF_TEST_CASE_BODY(search_paths_and_layout) {
  auto p = specSearchPaths("/home/alice", "firefox");
  ATF_REQUIRE_EQ(p.size(), 3u);
  ATF_REQUIRE_EQ(p[0], "/home/alice/.config/crate/profiles/firefox.yml");
  ATF_REQUIRE_EQ(p[1], "/usr/local/share/crate/profiles/firefox.yml");
  ATF_REQUIRE_EQ(p[2], "/usr/local/share/examples/crate/firefox.yml");
  ATF_REQUIRE_EQ(localOverridePath("/home/alice", "firefox"),
                 "/home/alice/.config/crate/profiles/firefox.local.yml");
  ATF_REQUIRE_EQ(buildDir("/home/alice"), "/home/alice/.local/share/crate/profiles");
  ATF_REQUIRE_EQ(cratePath("/home/alice", "firefox"),
                 "/home/alice/.local/share/crate/profiles/firefox.crate");
  ATF_REQUIRE_EQ(mergedSpecPath("/home/alice", "firefox"),
                 "/home/alice/.local/share/crate/profiles/firefox.yml");
  // root's home works the same way
  ATF_REQUIRE_EQ(specSearchPaths("/root", "nginx")[0], "/root/.config/crate/profiles/nginx.yml");
}

ATF_TEST_CASE_WITHOUT_HEAD(local_forbidden_keys);
ATF_TEST_CASE_BODY(local_forbidden_keys) {
  for (const char *k : {"security_advanced", "dbus", "base", "scripts", "encrypted",
                        "socket_proxy", "devices"})
    if (checkLocalTopLevelKey(k).empty()) ATF_FAIL(std::string(k) + " must be refused in a .local");
  for (const char *k : {"pkg", "options", "dirs", "files", "run", "limits", "name", "x11", "gui",
                        "healthcheck", "restart", "clipboard", "dns_filter", "cow",
                        "security", "ipc", "zfs"})   // the sections themselves; see below
    if (!checkLocalTopLevelKey(k).empty()) ATF_FAIL(std::string(k) + " should be allowed in a .local");
  ATF_REQUIRE_EQ(forbiddenLocalKeys().size(), 17u);
  ATF_REQUIRE(checkLocalTopLevelKey("dbus").find("dbus") != std::string::npos);
}

// 1.1.71: the parser's '-' spelling, nested keys, duplicates
ATF_TEST_CASE_WITHOUT_HEAD(local_forbidden_key_spellings_and_paths);
ATF_TEST_CASE_BODY(local_forbidden_key_spellings_and_paths) {
  for (const char *k : {"security-advanced", "socket-proxy"})
    if (checkLocalTopLevelKey(k).empty()) ATF_FAIL(std::string(k) + " must be refused like its '_' form");
  ATF_REQUIRE(checkLocalTopLevelKey("security-advanced").find("security_advanced") != std::string::npos);
  for (auto p : std::vector<std::vector<std::string>>{
         {"security", "securelevel"}, {"security", "enforce-statfs"}, {"security", "allow_chflags"},
         {"security", "allow-mlock"}, {"security", "children_max"}, {"security", "allow_set_hostname"},
         {"security", "allow_quotas"}, {"ipc", "raw_sockets"}, {"ipc", "raw-sockets"},
         {"ipc", "sysvipc"}, {"zfs", "datasets"}})
    if (checkLocalKeyPath(p).empty()) ATF_FAIL(p[0] + "/" + p[1] + " must be refused in a .local");
  for (auto p : std::vector<std::vector<std::string>>{
         {"security", "cpuset"}, {"ipc", "mqueue"}, {"dirs", "share"}, {"run", "command"},
         {"limits", "memoryuse"}, {"securelevel"}})
    if (!checkLocalKeyPath(p).empty()) ATF_FAIL(p[0] + (p.size() > 1 ? "/" + p[1] : "") + " should be allowed");
  ATF_REQUIRE_EQ(normaliseKey("dns-filter"), "dns_filter");
}

ATF_TEST_CASE_WITHOUT_HEAD(local_duplicate_keys);
ATF_TEST_CASE_BODY(local_duplicate_keys) {
  ATF_REQUIRE_EQ(checkLocalDuplicateKeys({"pkg", "dirs", "run"}, ""), "");
  ATF_REQUIRE(!checkLocalDuplicateKeys({"share", "share"}, "dirs").empty());
  ATF_REQUIRE(checkLocalDuplicateKeys({"share", "share"}, "dirs").find("dirs/share") != std::string::npos);
  // the two spellings of one key are one key
  ATF_REQUIRE(!checkLocalDuplicateKeys({"dns_filter", "pkg", "dns-filter"}, "").empty());
  ATF_REQUIRE(checkLocalDuplicateKeys({"dns_filter", "pkg", "dns-filter"}, "").find("'dns_filter' too")
              != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(local_share_host_paths);
ATF_TEST_CASE_BODY(local_share_host_paths) {
  const std::string home = "/home/alice";
  for (const char *ok : {"$HOME", "$HOME/Downloads", "$HOME/a/b", "/home/alice", "/home/alice/Pictures"})
    if (!checkLocalShareHostPath(ok, home).empty())
      ATF_FAIL(std::string(ok) + " should be accepted: " + checkLocalShareHostPath(ok, home));
  for (const char *bad : {"", "/etc", "/home", "/home/alicex/x", "/home/bob", "$HOMER/x", "$HOME/../bob",
                          "~/Downloads", "Downloads", "$XDG_DATA_HOME/x", "/home/alice/..", "/home/alice/x\n"})
    if (checkLocalShareHostPath(bad, home).empty())
      ATF_FAIL(std::string("'") + bad + "' should be rejected");
  // a trailing slash on the home directory does not change the answer
  ATF_REQUIRE_EQ(checkLocalShareHostPath("/home/alice/x", "/home/alice/"), "");
  // without a usable home, only $HOME forms are acceptable
  ATF_REQUIRE_EQ(checkLocalShareHostPath("$HOME/x", ""), "");
  ATF_REQUIRE(!checkLocalShareHostPath("/home/alice/x", "").empty());
  ATF_REQUIRE(!checkLocalShareHostPath("/x", "/").empty());
  ATF_REQUIRE(checkLocalShareHostPath("/etc", home).find("/etc") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(rebuild_decision);
ATF_TEST_CASE_BODY(rebuild_decision) {
  using A = CacheAction;
  // 1.1.71: keyed by content; mtimes only order the .crate after its merged spec
  ATF_REQUIRE(cacheAction(-1, -1, "", "k") == A::RewriteAndBuild);     // first run
  ATF_REQUIRE(cacheAction(500, 100, "", "k") == A::RewriteAndBuild);   // 1.1.70 cache: no key yet
  ATF_REQUIRE(cacheAction(500, 100, "old", "k") == A::RewriteAndBuild);// spec, .local, vars or version changed
  ATF_REQUIRE(cacheAction(500, -1, "k", "k") == A::RewriteAndBuild);   // merged spec deleted
  ATF_REQUIRE(cacheAction(-1, 100, "k", "k") == A::Build);             // root has not built it yet
  ATF_REQUIRE(cacheAction(100, 100, "k", "k") == A::Build);            // not newer than its spec
  ATF_REQUIRE(cacheAction(50, 100, "k", "k") == A::Build);             // an older archive
  ATF_REQUIRE(cacheAction(101, 100, "k", "k") == A::UpToDate);
  ATF_REQUIRE(cacheAction(101, 100, "", "") == A::RewriteAndBuild);    // no key computed: never trust
}

ATF_TEST_CASE_WITHOUT_HEAD(cache_key_input);
ATF_TEST_CASE_BODY(cache_key_input) {
  const std::string spec = "pkg:\n  install: [vim]\n";
  const auto base = cacheKeyInput(spec, {}, "1.1.71");
  ATF_REQUIRE(base != cacheKeyInput(spec, {}, "1.1.72"));                        // version
  ATF_REQUIRE(base != cacheKeyInput(spec + "#\n", {}, "1.1.71"));               // text
  ATF_REQUIRE(base != cacheKeyInput(spec, {{"PG_VERSION", "16"}}, "1.1.71"));    // a var
  ATF_REQUIRE(cacheKeyInput(spec, {{"A", "1"}}, "v") != cacheKeyInput(spec, {{"A", "2"}}, "v"));
  // length prefixes: "A=1 B" is not the same as A="1 B"
  ATF_REQUIRE(cacheKeyInput(spec, {{"A", "x 1:y"}}, "v") != cacheKeyInput(spec, {{"A", "x"}, {"y", ""}}, "v"));
  ATF_REQUIRE_EQ(base, cacheKeyInput(spec, {}, "1.1.71"));                       // deterministic
  ATF_REQUIRE_EQ(cacheKeyPath("/home/alice", "firefox"), "/home/alice/.local/share/crate/profiles/firefox.key");
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, profile_names);
  ATF_ADD_TEST_CASE(tcs, search_paths_and_layout);
  ATF_ADD_TEST_CASE(tcs, local_forbidden_keys);
  ATF_ADD_TEST_CASE(tcs, local_forbidden_key_spellings_and_paths);
  ATF_ADD_TEST_CASE(tcs, local_duplicate_keys);
  ATF_ADD_TEST_CASE(tcs, local_share_host_paths);
  ATF_ADD_TEST_CASE(tcs, rebuild_decision);
  ATF_ADD_TEST_CASE(tcs, cache_key_input);
}
