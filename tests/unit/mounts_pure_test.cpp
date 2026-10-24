// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "mounts_pure.h"

#include <atf-c++.hpp>

#include <string>

using namespace MountsPure;

ATF_TEST_CASE_WITHOUT_HEAD(ro_suffix_and_flag);
ATF_TEST_CASE_BODY(ro_suffix_and_flag) {
  std::string p = "$HOME/Documents:ro";
  ATF_REQUIRE(splitRoSuffix(p));
  ATF_REQUIRE_EQ(p, std::string("$HOME/Documents"));
  p = "/mnt/music:rw";
  ATF_REQUIRE(!splitRoSuffix(p));
  ATF_REQUIRE_EQ(p, std::string("/mnt/music"));
  p = "/mnt/music";
  ATF_REQUIRE(!splitRoSuffix(p));
  ATF_REQUIRE_EQ(p, std::string("/mnt/music"));
  p = ":ro";                       // nothing before the suffix: not a suffix
  ATF_REQUIRE(!splitRoSuffix(p));
  ATF_REQUIRE_EQ(p, std::string(":ro"));
  p = "/srv/x:ro:ro";              // one suffix stripped only
  ATF_REQUIRE(splitRoSuffix(p));
  ATF_REQUIRE_EQ(p, std::string("/srv/x:ro"));

  bool ro = false; std::string err;
  ATF_REQUIRE(parseRoFlag("ro", ro, err)); ATF_REQUIRE(ro);
  ATF_REQUIRE(parseRoFlag("rw", ro, err)); ATF_REQUIRE(!ro);
  ATF_REQUIRE(!parseRoFlag("readonly", ro, err));
  ATF_REQUIRE(err.find("readonly") != std::string::npos);
  ATF_REQUIRE(!parseRoFlag("", ro, err));
}

ATF_TEST_CASE_WITHOUT_HEAD(tmpfs_size_and_path);
ATF_TEST_CASE_BODY(tmpfs_size_and_path) {
  ATF_REQUIRE_EQ(validateTmpfsSize(""), std::string());
  ATF_REQUIRE_EQ(validateTmpfsSize("512m"), std::string());
  ATF_REQUIRE_EQ(validateTmpfsSize("2G"), std::string());
  ATF_REQUIRE_EQ(validateTmpfsSize("1024"), std::string());
  ATF_REQUIRE_EQ(validateTmpfsSize("64k"), std::string());
  ATF_REQUIRE(!validateTmpfsSize("0").empty());
  ATF_REQUIRE(!validateTmpfsSize("00m").empty());
  ATF_REQUIRE(!validateTmpfsSize("m").empty());
  ATF_REQUIRE(!validateTmpfsSize("512mb").empty());
  ATF_REQUIRE(!validateTmpfsSize("512 m").empty());
  ATF_REQUIRE(!validateTmpfsSize("-5").empty());
  ATF_REQUIRE(!validateTmpfsSize("1t").empty());
  ATF_REQUIRE(!validateTmpfsSize("123456789012345678901").empty());

  ATF_REQUIRE_EQ(validateTmpfsPath("/tmp"), std::string());
  ATF_REQUIRE_EQ(validateTmpfsPath("/var/tmp"), std::string());
  ATF_REQUIRE_EQ(validateTmpfsPath("$HOME/.cache"), std::string());
  ATF_REQUIRE_EQ(validateTmpfsPath("$HOME/.cache/mozilla"), std::string());
  ATF_REQUIRE_EQ(validateTmpfsPath("/usr/local/www/tmp"), std::string());
  ATF_REQUIRE(!validateTmpfsPath("").empty());
  ATF_REQUIRE(!validateTmpfsPath("tmp").empty());
  ATF_REQUIRE(!validateTmpfsPath("/").empty());
  ATF_REQUIRE(!validateTmpfsPath("/tmp/").empty());
  ATF_REQUIRE(!validateTmpfsPath("/tmp/../etc").empty());
  ATF_REQUIRE(!validateTmpfsPath("/tmp//x").empty());
  ATF_REQUIRE(!validateTmpfsPath("$HOME").empty());
  ATF_REQUIRE(!validateTmpfsPath("$HOMEx/y").empty());
  for (const char *f : {"/dev", "/proc", "/etc", "/bin", "/sbin", "/lib", "/libexec", "/usr", "/usr/local", "/var/run"})
    ATF_REQUIRE(validateTmpfsPath(f).find("hide") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(etc_keep_names);
ATF_TEST_CASE_BODY(etc_keep_names) {
  for (const char *ok : {"localtime", "hosts", "resolv.conf", "ssl", "pkg", "login.conf", "X11", "rc.conf.d", "mail.rc", "crontab@x"})
    ATF_REQUIRE_EQ(validateEtcKeepName(ok), std::string());
  ATF_REQUIRE(!validateEtcKeepName("").empty());
  ATF_REQUIRE(!validateEtcKeepName(".").empty());
  ATF_REQUIRE(!validateEtcKeepName("..").empty());
  ATF_REQUIRE(!validateEtcKeepName("ssl/certs").empty());     // one component only
  ATF_REQUIRE(!validateEtcKeepName("../passwd").empty());
  ATF_REQUIRE(!validateEtcKeepName("/etc/hosts").empty());
  ATF_REQUIRE(!validateEtcKeepName("hosts; rm -rf /").empty());
  ATF_REQUIRE(!validateEtcKeepName("a b").empty());
  ATF_REQUIRE(!validateEtcKeepName(std::string(129, 'a')).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(under_and_params);
ATF_TEST_CASE_BODY(under_and_params) {
  ATF_REQUIRE(isUnder("/home/alice/.cache", "/home/alice"));
  ATF_REQUIRE(isUnder("/home/alice", "/home/alice"));
  ATF_REQUIRE(!isUnder("/home/alicex/.cache", "/home/alice"));
  ATF_REQUIRE(!isUnder("/tmp", "/home/alice"));
  ATF_REQUIRE(isUnder("/anything", "/"));
  ATF_REQUIRE(!isUnder("/x", ""));

  auto home = tmpfsParams("256m", true, 1001, 1001);
  ATF_REQUIRE_EQ(home.size(), 4u);
  ATF_REQUIRE_EQ(home[0].first, std::string("size")); ATF_REQUIRE_EQ(home[0].second, std::string("256m"));
  ATF_REQUIRE_EQ(home[1].first, std::string("uid"));  ATF_REQUIRE_EQ(home[1].second, std::string("1001"));
  ATF_REQUIRE_EQ(home[2].first, std::string("gid"));
  ATF_REQUIRE_EQ(home[3].first, std::string("mode")); ATF_REQUIRE_EQ(home[3].second, std::string("0700"));
  auto tmp = tmpfsParams("", false, 1001, 1001);
  ATF_REQUIRE_EQ(tmp.size(), 1u);
  ATF_REQUIRE_EQ(tmp[0].first, std::string("mode")); ATF_REQUIRE_EQ(tmp[0].second, std::string("01777"));

  ATF_REQUIRE_EQ(validateDecimal("0", "uid"), std::string());
  ATF_REQUIRE_EQ(validateDecimal("4294967295", "uid"), std::string());
  ATF_REQUIRE(!validateDecimal("", "uid").empty());
  ATF_REQUIRE(!validateDecimal("-1", "uid").empty());
  ATF_REQUIRE(!validateDecimal("12345678901", "uid").empty());
  ATF_REQUIRE_EQ(validateOctalMode("0700"), std::string());
  ATF_REQUIRE_EQ(validateOctalMode("01777"), std::string());
  ATF_REQUIRE_EQ(validateOctalMode("755"), std::string());
  ATF_REQUIRE(!validateOctalMode("8").empty());
  ATF_REQUIRE(!validateOctalMode("0778").empty());
  ATF_REQUIRE(!validateOctalMode("017777").empty());
  ATF_REQUIRE(!validateOctalMode("rwx").empty());
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, ro_suffix_and_flag);
  ATF_ADD_TEST_CASE(tcs, tmpfs_size_and_path);
  ATF_ADD_TEST_CASE(tcs, etc_keep_names);
  ATF_ADD_TEST_CASE(tcs, under_and_params);
}
