// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.58: thin jails on nullfs (base/mode: host-ro) — pure helpers.

#include "thin_jail_pure.h"

#include <atf-c++.hpp>

#include <algorithm>
#include <string>

using namespace ThinJailPure;

ATF_TEST_CASE_WITHOUT_HEAD(default_dirs_are_valid_and_exclude_usr_local);
ATF_TEST_CASE_BODY(default_dirs_are_valid_and_exclude_usr_local) {
  auto &d = defaultHostDirs();
  ATF_REQUIRE(!d.empty());
  ATF_REQUIRE_EQ(validateHostDirs(d), "");
  for (auto &x : d) {
    ATF_REQUIRE(x != "/usr");
    ATF_REQUIRE(x != "/usr/local");
    ATF_REQUIRE(x != "/etc");
  }
  ATF_REQUIRE(std::find(d.begin(), d.end(), "/bin") != d.end());
  ATF_REQUIRE(std::find(d.begin(), d.end(), "/usr/lib") != d.end());
  ATF_REQUIRE(isOptionalHostDir("/usr/lib32"));
  ATF_REQUIRE(isOptionalHostDir("/rescue"));
  ATF_REQUIRE(!isOptionalHostDir("/bin"));
  ATF_REQUIRE(!isOptionalHostDir("/usr/lib"));
}

ATF_TEST_CASE_WITHOUT_HEAD(validate_host_dir_rejects_bad_paths);
ATF_TEST_CASE_BODY(validate_host_dir_rejects_bad_paths) {
  ATF_REQUIRE_EQ(validateHostDir("/usr/bin"), "");
  ATF_REQUIRE_EQ(validateHostDir("/opt/tools"), "");
  ATF_REQUIRE(!validateHostDir("").empty());
  ATF_REQUIRE(!validateHostDir("usr/bin").empty());
  ATF_REQUIRE(!validateHostDir("/").empty());
  ATF_REQUIRE(!validateHostDir("/usr").empty());
  ATF_REQUIRE(!validateHostDir("/usr/bin/").empty());
  ATF_REQUIRE(!validateHostDir("/usr//bin").empty());
  ATF_REQUIRE(!validateHostDir("/usr/./bin").empty());
  ATF_REQUIRE(!validateHostDir("/usr/../etc").empty());
  ATF_REQUIRE(!validateHostDir("/usr/bin\n").empty());
  // writable layer, exact and nested
  for (const char *w : {"/etc", "/etc/ssh", "/var", "/var/db/pkg", "/tmp", "/root", "/home",
                        "/home/alice", "/usr/local", "/usr/local/bin", "/usr/home", "/dev", "/proc",
                        "/mnt", "/media"})
    if (validateHostDir(w).empty()) ATF_FAIL(std::string(w) + " should be rejected");
  // a sibling that merely shares a prefix is fine
  ATF_REQUIRE_EQ(validateHostDir("/etcetera"), "");
  ATF_REQUIRE_EQ(validateHostDir("/usr/localhost"), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(validate_host_dirs_list_rules);
ATF_TEST_CASE_BODY(validate_host_dirs_list_rules) {
  ATF_REQUIRE(!validateHostDirs({}).empty());
  ATF_REQUIRE(!validateHostDirs({"/bin", "/bin"}).empty());
  ATF_REQUIRE(!validateHostDirs({"/usr/lib", "/usr/lib/compat"}).empty());
  ATF_REQUIRE(!validateHostDirs({"/usr/lib/compat", "/usr/lib"}).empty());
  ATF_REQUIRE_EQ(validateHostDirs({"/usr/lib", "/usr/lib32"}), "");
  ATF_REQUIRE(!validateHostDirs({"/bin", "/etc"}).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(directories_and_mount_plan);
ATF_TEST_CASE_BODY(directories_and_mount_plan) {
  auto dirs = directoriesToCreate({"/usr/bin", "/bin", "/usr/local" /* already there */});
  // the fixed skeleton first, then the host dirs without duplicates
  ATF_REQUIRE(std::find(dirs.begin(), dirs.end(), "/dev") != dirs.end());
  ATF_REQUIRE(std::find(dirs.begin(), dirs.end(), "/usr") != dirs.end());
  ATF_REQUIRE_EQ(std::count(dirs.begin(), dirs.end(), "/usr/local"), 1);
  ATF_REQUIRE(std::find(dirs.begin(), dirs.end(), "/usr/bin") != dirs.end());

  auto plan = mountPlan("/var/run/crate/jail-x-1", {"/usr/lib32", "/bin", "/usr/lib"});
  ATF_REQUIRE_EQ(plan.size(), 3u);
  ATF_REQUIRE_EQ(plan[0].first, "/var/run/crate/jail-x-1/bin");
  ATF_REQUIRE_EQ(plan[0].second, "/bin");
  ATF_REQUIRE_EQ(plan[1].second, "/usr/lib");
  ATF_REQUIRE_EQ(plan[2].second, "/usr/lib32");
  // skeleton members are the ./-prefixed tar member names
  for (auto &m : baseArchiveSkeletonMembers())
    ATF_REQUIRE_EQ(m.substr(0, 2), "./");
}

ATF_TEST_CASE_WITHOUT_HEAD(manifest_round_trip);
ATF_TEST_CASE_BODY(manifest_round_trip) {
  Manifest m;
  m.osrelease = "14.2-RELEASE-p3";
  m.hostDirs = defaultHostDirs();
  auto text = serializeManifest(m);
  ATF_REQUIRE_EQ(text.substr(0, 21), "# crate thin jail v1\n");
  ATF_REQUIRE(text.find("mode\thost-ro\n") != std::string::npos);
  ATF_REQUIRE(text.find("osrelease\t14.2-RELEASE-p3\n") != std::string::npos);
  ATF_REQUIRE(text.find("hostdir\t/usr/share\n") != std::string::npos);

  Manifest back; std::string err;
  if (!parseManifest(text, back, err)) ATF_FAIL(err);
  ATF_REQUIRE_EQ(back.mode, "host-ro");
  ATF_REQUIRE_EQ(back.osrelease, m.osrelease);
  ATF_REQUIRE(back.hostDirs == m.hostDirs);
  // CRLF tolerated, blank lines and comments skipped
  std::string crlf;
  for (char c : text) { if (c == '\n') crlf += "\r\n"; else crlf += c; }
  crlf += "\n# trailing comment\n";
  if (!parseManifest(crlf, back, err)) ATF_FAIL(err);
  ATF_REQUIRE_EQ(back.hostDirs.size(), m.hostDirs.size());
}

ATF_TEST_CASE_WITHOUT_HEAD(manifest_rejects_malformed);
ATF_TEST_CASE_BODY(manifest_rejects_malformed) {
  Manifest out; std::string err;
  const std::string good = "# crate thin jail v1\nmode\thost-ro\nosrelease\t14.2-RELEASE\nhostdir\t/bin\n";
  ATF_REQUIRE(parseManifest(good, out, err));
  ATF_REQUIRE(!parseManifest("", out, err));
  ATF_REQUIRE(!parseManifest("mode\thost-ro\nosrelease\t14.2-RELEASE\nhostdir\t/bin\n", out, err)); // no header
  ATF_REQUIRE(!parseManifest("# crate thin jail v1\nmode\tfull\nosrelease\t14.2\nhostdir\t/bin\n", out, err));
  ATF_REQUIRE(!parseManifest("# crate thin jail v1\nmode\thost-ro\nhostdir\t/bin\n", out, err)); // no osrelease
  ATF_REQUIRE(!parseManifest("# crate thin jail v1\nmode\thost-ro\nosrelease\t14.2\n", out, err)); // no dirs
  ATF_REQUIRE(!parseManifest("# crate thin jail v1\nmode\thost-ro\nosrelease\t14.2\nhostdir\t/etc\n", out, err));
  ATF_REQUIRE(!parseManifest("# crate thin jail v1\nmode\thost-ro\nosrelease\t14.2\nhostdir\t/usr/../etc\n", out, err));
  ATF_REQUIRE(!parseManifest("# crate thin jail v1\nmode\thost-ro\nosrelease\t14.2\nhostdir /bin\n", out, err)); // space, not tab
  ATF_REQUIRE(!parseManifest("# crate thin jail v1\nmode\thost-ro\nosrelease\t14.2\nhostdir\t/bin\ncolour\tblue\n", out, err));
  ATF_REQUIRE(!parseManifest("# crate thin jail v1\nmode\thost-ro\nmode\thost-ro\nosrelease\t14.2\nhostdir\t/bin\n", out, err));
  ATF_REQUIRE(!parseManifest("# crate thin jail v1\nmode\thost-ro\nosrelease\t14.2 RELEASE\nhostdir\t/bin\n", out, err));
  ATF_REQUIRE(!parseManifest(std::string(kManifestMaxBytes + 1, '#'), out, err));
  // the error text names the problem
  ATF_REQUIRE(!parseManifest("# crate thin jail v1\nmode\tfull\nosrelease\t14.2\nhostdir\t/bin\n", out, err));
  ATF_REQUIRE(err.find("mode") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(release_compatibility);
ATF_TEST_CASE_BODY(release_compatibility) {
  ATF_REQUIRE_EQ(majorMinor("14.2-RELEASE-p3"), "14.2");
  ATF_REQUIRE_EQ(majorMinor("15.0-CURRENT"), "15.0");
  ATF_REQUIRE_EQ(majorMinor("15.0"), "15.0");
  ATF_REQUIRE_EQ(majorMinor("garbage"), "");
  ATF_REQUIRE_EQ(majorMinor("14-RELEASE"), "");
  ATF_REQUIRE_EQ(majorMinor(""), "");

  ATF_REQUIRE_EQ(releaseMismatchWarning("14.2-RELEASE-p3", "14.2-RELEASE-p5"), "");
  ATF_REQUIRE_EQ(releaseMismatchWarning("", "14.2-RELEASE"), "");          // unknown: no noise
  auto minor = releaseMismatchWarning("14.1-RELEASE", "14.2-RELEASE-p1");
  ATF_REQUIRE(!minor.empty());
  ATF_REQUIRE(minor.find("Minor") != std::string::npos);
  auto major = releaseMismatchWarning("14.2-RELEASE", "15.0-RELEASE");
  ATF_REQUIRE(!major.empty());
  ATF_REQUIRE(major.find("major") != std::string::npos);
  ATF_REQUIRE(major.find("14.2-RELEASE") != std::string::npos);
  ATF_REQUIRE(major.find("15.0-RELEASE") != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, default_dirs_are_valid_and_exclude_usr_local);
  ATF_ADD_TEST_CASE(tcs, validate_host_dir_rejects_bad_paths);
  ATF_ADD_TEST_CASE(tcs, validate_host_dirs_list_rules);
  ATF_ADD_TEST_CASE(tcs, directories_and_mount_plan);
  ATF_ADD_TEST_CASE(tcs, manifest_round_trip);
  ATF_ADD_TEST_CASE(tcs, manifest_rejects_malformed);
  ATF_ADD_TEST_CASE(tcs, release_compatibility);
}
