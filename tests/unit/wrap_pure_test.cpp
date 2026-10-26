// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "wrap_pure.h"

#include <atf-c++.hpp>

#include <string>

using namespace WrapPure;

ATF_TEST_CASE_WITHOUT_HEAD(paths);
ATF_TEST_CASE_BODY(paths) {
  ATF_REQUIRE_EQ(binDir("/home/alice"), std::string("/home/alice/.local/bin"));
  ATF_REQUIRE_EQ(launcherPath("/home/alice", "firefox"), std::string("/home/alice/.local/bin/firefox"));
  ATF_REQUIRE_EQ(applicationsDir("/home/alice", ""), std::string("/home/alice/.local/share/applications"));
  ATF_REQUIRE_EQ(applicationsDir("/home/alice", "/data/xdg/"), std::string("/data/xdg/applications"));
  ATF_REQUIRE_EQ(applicationsDir("/home/alice", "relative"), std::string("/home/alice/.local/share/applications"));
  ATF_REQUIRE_EQ(desktopFileName("firefox-gpu"), std::string("crate-firefox-gpu.desktop"));
  ATF_REQUIRE_EQ(desktopPath("/home/alice", "", "firefox"),
                 std::string("/home/alice/.local/share/applications/crate-firefox.desktop"));

  ATF_REQUIRE_EQ(validateLauncherName("firefox"), std::string());
  ATF_REQUIRE_EQ(validateLauncherName("sfetch_2"), std::string());
  ATF_REQUIRE(!validateLauncherName("crate").empty());
  ATF_REQUIRE(!validateLauncherName("").empty());
  ATF_REQUIRE(!validateLauncherName("../bin").empty());
  ATF_REQUIRE(!validateLauncherName("a b").empty());
  ATF_REQUIRE(!validateLauncherName("-x").empty());
  ATF_REQUIRE(!validateLauncherName("x.local").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(launcher_roundtrip);
ATF_TEST_CASE_BODY(launcher_roundtrip) {
  const std::string l = renderLauncher("firefox", "/usr/local/bin/crate", "1.1.66");
  ATF_REQUIRE(l.compare(0, 10, "#!/bin/sh\n") == 0);
  ATF_REQUIRE(l.find("# crate wrap: firefox (crate 1.1.66)\n") != std::string::npos);
  ATF_REQUIRE(l.find("exec '/usr/local/bin/crate' run firefox -- \"$@\"\n") != std::string::npos);
  std::string p;
  ATF_REQUIRE(launcherProfile(l, p));
  ATF_REQUIRE_EQ(p, std::string("firefox"));

  // a crate path with a quote is still a valid sh word
  const std::string odd = renderLauncher("x", "/opt/it's/crate", "1");
  ATF_REQUIRE(odd.find("exec '/opt/it'\\''s/crate' run x") != std::string::npos);

  // not ours: no marker, marker too far down, marker naming garbage
  ATF_REQUIRE(!launcherProfile("#!/bin/sh\nexec firefox \"$@\"\n", p));
  ATF_REQUIRE(!launcherProfile("", p));
  ATF_REQUIRE(!launcherProfile("#!/bin/sh\n\n\n\n\n# crate wrap: late\n", p));
  ATF_REQUIRE(!launcherProfile("#!/bin/sh\n# crate wrap: ../etc (crate 1)\n", p));
  ATF_REQUIRE(!launcherProfile("#!/bin/sh\n# crate wrap: \n", p));
  ATF_REQUIRE_EQ(p, std::string("firefox"));   // untouched on failure
  // an older marker without the version suffix still counts
  ATF_REQUIRE(launcherProfile("#!/bin/sh\n# crate wrap: mpv\nexec crate run mpv -- \"$@\"\n", p));
  ATF_REQUIRE_EQ(p, std::string("mpv"));
}

ATF_TEST_CASE_WITHOUT_HEAD(desktop_roundtrip);
ATF_TEST_CASE_BODY(desktop_roundtrip) {
  const std::string d = renderDesktop("firefox-gpu", "/usr/local/bin/crate", "1.1.66", false);
  ATF_REQUIRE(d.compare(0, 16, "[Desktop Entry]\n") == 0);
  ATF_REQUIRE(d.find("Type=Application\n") != std::string::npos);
  ATF_REQUIRE(d.find("Name=Firefox Gpu (crate)\n") != std::string::npos);
  ATF_REQUIRE(d.find("Exec=/usr/local/bin/crate run firefox-gpu -- %U\n") != std::string::npos);
  ATF_REQUIRE(d.find("Icon=firefox-gpu\n") != std::string::npos);
  ATF_REQUIRE(d.find("Terminal=false\n") != std::string::npos);
  ATF_REQUIRE(d.find("X-Crate-Profile=firefox-gpu\n") != std::string::npos);
  std::string p;
  ATF_REQUIRE(desktopProfile(d, p));
  ATF_REQUIRE_EQ(p, std::string("firefox-gpu"));

  const std::string t = renderDesktop("fetch", "/usr/local/bin/crate", "1.1.66", true, "utilities-terminal");
  ATF_REQUIRE(t.find("Terminal=true\n") != std::string::npos);
  ATF_REQUIRE(t.find("Icon=utilities-terminal\n") != std::string::npos);

  // a crate path with a space is quoted in Exec=
  const std::string sp = renderDesktop("x", "/opt/my tools/crate", "1", false);
  ATF_REQUIRE(sp.find("Exec=\"/opt/my tools/crate\" run x -- %U\n") != std::string::npos);

  // not ours / foreign group
  ATF_REQUIRE(!desktopProfile("[Desktop Entry]\nType=Application\nName=Firefox\nExec=firefox %u\n", p));
  ATF_REQUIRE(!desktopProfile("[Desktop Action new]\nX-Crate-Profile=firefox\n", p));
  ATF_REQUIRE(!desktopProfile("[Desktop Entry]\nX-Crate-Profile=../x\n", p));
  ATF_REQUIRE(!desktopProfile("", p));
  ATF_REQUIRE_EQ(p, std::string("firefox-gpu"));
  ATF_REQUIRE(desktopProfile("[Desktop Entry]\r\n  X-Crate-Profile = mpv \r\n", p) == false);   // no spaces around '='
  ATF_REQUIRE(desktopProfile("[Desktop Entry]\r\nX-Crate-Profile=mpv\r\n", p));
  ATF_REQUIRE_EQ(p, std::string("mpv"));

  ATF_REQUIRE_EQ(displayName("firefox"), std::string("Firefox (crate)"));
  ATF_REQUIRE_EQ(displayName("lxqt-desktop_nested"), std::string("Lxqt Desktop Nested (crate)"));
  ATF_REQUIRE_EQ(displayName("X11"), std::string("X11 (crate)"));
}

ATF_TEST_CASE_WITHOUT_HEAD(path_and_list);
ATF_TEST_CASE_BODY(path_and_list) {
  ATF_REQUIRE(pathHasDir("/home/a/.local/bin:/usr/local/bin:/usr/bin", "/home/a/.local/bin"));
  ATF_REQUIRE(pathHasDir("/usr/bin:/home/a/.local/bin/", "/home/a/.local/bin"));
  ATF_REQUIRE(pathHasDir("/usr/bin:/home/a/.local/bin", "/home/a/.local/bin/"));
  ATF_REQUIRE(!pathHasDir("/home/a/.local/binx:/usr/bin", "/home/a/.local/bin"));
  ATF_REQUIRE(!pathHasDir("", "/home/a/.local/bin"));
  ATF_REQUIRE(!pathHasDir("/usr/bin", "/home/a/.local/bin"));

  std::vector<Entry> es = {
    {"firefox", "/h/.local/bin/firefox", "/h/.local/share/applications/crate-firefox.desktop"},
    {"fetch", "/h/.local/bin/sfetch", ""},
    {"mpv", "", "/h/.local/share/applications/crate-mpv.desktop"},
    {"odd", "", ""},
  };
  const std::string out = renderList(es);
  ATF_REQUIRE(out.compare(0, 7, "PROFILE") == 0);
  ATF_REQUIRE(out.find("firefox  /h/.local/bin/firefox\n         /h/.local/share/applications/crate-firefox.desktop\n") != std::string::npos);
  ATF_REQUIRE(out.find("fetch    /h/.local/bin/sfetch\n") != std::string::npos);
  ATF_REQUIRE(out.find("mpv      /h/.local/share/applications/crate-mpv.desktop\n") != std::string::npos);
  ATF_REQUIRE(out.find("odd      -\n") != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, paths);
  ATF_ADD_TEST_CASE(tcs, launcher_roundtrip);
  ATF_ADD_TEST_CASE(tcs, desktop_roundtrip);
  ATF_ADD_TEST_CASE(tcs, path_and_list);
}
