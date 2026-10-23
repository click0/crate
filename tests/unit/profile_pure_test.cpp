// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.59: per-application profiles (`crate run <name>`) — pure rules.

#include "profile_pure.h"

#include <atf-c++.hpp>

#include <string>

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
  for (const char *k : {"security_advanced", "dbus", "base", "scripts", "encrypted", "securelevel",
                        "socket_proxy"})
    if (checkLocalTopLevelKey(k).empty()) ATF_FAIL(std::string(k) + " must be refused in a .local");
  for (const char *k : {"pkg", "options", "dirs", "files", "run", "limits", "name", "x11", "gui",
                        "healthcheck", "restart", "clipboard", "dns_filter", "cow"})
    if (!checkLocalTopLevelKey(k).empty()) ATF_FAIL(std::string(k) + " should be allowed in a .local");
  ATF_REQUIRE_EQ(forbiddenLocalKeys().size(), 7u);
  ATF_REQUIRE(checkLocalTopLevelKey("dbus").find("dbus") != std::string::npos);
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
  ATF_REQUIRE(needsRebuild(-1, 100, -1));       // no crate yet
  ATF_REQUIRE(needsRebuild(-1, 100, 50));
  ATF_REQUIRE(!needsRebuild(200, 100, -1));     // crate newer than the profile, no .local
  ATF_REQUIRE(needsRebuild(200, 300, -1));      // profile edited
  ATF_REQUIRE(needsRebuild(200, 100, 250));     // .local edited
  ATF_REQUIRE(!needsRebuild(200, 100, 150));    // both older
  ATF_REQUIRE(!needsRebuild(200, 200, 200));    // equal mtimes: keep the crate
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, profile_names);
  ATF_ADD_TEST_CASE(tcs, search_paths_and_layout);
  ATF_ADD_TEST_CASE(tcs, local_forbidden_keys);
  ATF_ADD_TEST_CASE(tcs, local_share_host_paths);
  ATF_ADD_TEST_CASE(tcs, rebuild_decision);
}
