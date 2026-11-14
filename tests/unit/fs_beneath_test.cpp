// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.76: FsBeneath — host-side writes into a jail tree must not follow
// a symlink the jail made, in any component. Runs on a scratch tree
// under the test's working directory.

#include "fs_beneath.h"

#include <atf-c++.hpp>

#include <filesystem>
#include <functional>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

// A scratch tree: <cwd>/fsb.XXXXXX/{tree,host}. tree is the jail's
// root; host stands for a host directory a link could point at.
struct Scratch {
  std::string base, tree, host;
  Scratch() {
    char tmpl[] = "fsb.XXXXXX";
    ATF_REQUIRE(::mkdtemp(tmpl) != nullptr);
    base = std::filesystem::absolute(tmpl).string();
    tree = base + "/tree";
    host = base + "/host";
    ATF_REQUIRE(::mkdir(tree.c_str(), 0755) == 0);
    ATF_REQUIRE(::mkdir(host.c_str(), 0755) == 0);
    ATF_REQUIRE(::mkdir((tree + "/etc").c_str(), 0755) == 0);
    put(host + "/rc.conf", "host\n");
  }
  ~Scratch() { std::error_code ec; std::filesystem::remove_all(base, ec); }
  static void put(const std::string &p, const std::string &s) { std::ofstream(p) << s; }
  static std::string get(const std::string &p) {
    std::ifstream f(p); std::stringstream ss; ss << f.rdbuf(); return ss.str();
  }
};

bool throws(const std::function<void()> &f) {
  try { f(); } catch (const std::exception &) { return true; }
  return false;
}

}

ATF_TEST_CASE_WITHOUT_HEAD(split_relative);
ATF_TEST_CASE_BODY(split_relative) {
  std::vector<std::string> p;
  ATF_REQUIRE_EQ(FsBeneath::splitRelative("/etc/rc.conf", p), std::string());
  ATF_REQUIRE_EQ(p.size(), 2u);
  ATF_REQUIRE_EQ(p[0], std::string("etc"));
  ATF_REQUIRE_EQ(p[1], std::string("rc.conf"));
  ATF_REQUIRE_EQ(FsBeneath::splitRelative("etc//cron/tabs/", p), std::string());
  ATF_REQUIRE_EQ(p.size(), 3u);
  ATF_REQUIRE_EQ(p[2], std::string("tabs"));
  ATF_REQUIRE_EQ(FsBeneath::splitRelative("/.crate-initialized", p), std::string());
  ATF_REQUIRE_EQ(p.size(), 1u);
  ATF_REQUIRE(!FsBeneath::splitRelative("", p).empty());
  ATF_REQUIRE(!FsBeneath::splitRelative("/", p).empty());
  ATF_REQUIRE(!FsBeneath::splitRelative("///", p).empty());
  ATF_REQUIRE(!FsBeneath::splitRelative("/etc/../../etc/passwd", p).empty());
  ATF_REQUIRE(!FsBeneath::splitRelative("/etc/./rc.conf", p).empty());
  ATF_REQUIRE(!FsBeneath::splitRelative("..", p).empty());
  ATF_REQUIRE_EQ(FsBeneath::splitRelative("/etc/..rc", p), std::string());   // a name, not ".."
}

ATF_TEST_CASE_WITHOUT_HEAD(write_and_append);
ATF_TEST_CASE_BODY(write_and_append) {
  Scratch s;
  FsBeneath::writeFile(s.tree, "/etc/rc.conf", "a=1\n");
  FsBeneath::appendFile(s.tree, "/etc/rc.conf", "b=2\n");
  ATF_REQUIRE_EQ(Scratch::get(s.tree + "/etc/rc.conf"), std::string("a=1\nb=2\n"));
  FsBeneath::writeFile(s.tree, "/etc/rc.conf", "c\n");          // truncates
  ATF_REQUIRE_EQ(Scratch::get(s.tree + "/etc/rc.conf"), std::string("c\n"));
  FsBeneath::appendFile(s.tree, "/etc/new", "x");               // creates
  ATF_REQUIRE_EQ(Scratch::get(s.tree + "/etc/new"), std::string("x"));
  ATF_REQUIRE(throws([&] { FsBeneath::writeFile(s.tree, "/nodir/f", "x"); }));
}

// The finding: /etc -> <host dir> (an absolute link resolves against the
// host's root when the host walks it).
ATF_TEST_CASE_WITHOUT_HEAD(symlinked_directory_refused);
ATF_TEST_CASE_BODY(symlinked_directory_refused) {
  Scratch s;
  std::filesystem::remove_all(s.tree + "/etc");
  ATF_REQUIRE(::symlink(s.host.c_str(), (s.tree + "/etc").c_str()) == 0);
  ATF_REQUIRE(throws([&] { FsBeneath::appendFile(s.tree, "/etc/rc.conf", "evil\n"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::writeFile(s.tree, "/etc/rc.conf", "evil\n"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::copyIn(s.host + "/rc.conf", s.tree, "/etc/x", 0644); }));
  ATF_REQUIRE(throws([&] { FsBeneath::chmod(s.tree, "/etc/rc.conf", 0777); }));
  ATF_REQUIRE(throws([&] { FsBeneath::unlink(s.tree, "/etc/rc.conf"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::exists(s.tree, "/etc/rc.conf"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::mkdirs(s.tree, "/etc/unbound", 0755); }));
  ATF_REQUIRE_EQ(Scratch::get(s.host + "/rc.conf"), std::string("host\n"));
  ATF_REQUIRE(!std::filesystem::exists(s.host + "/x"));
  ATF_REQUIRE(!std::filesystem::exists(s.host + "/unbound"));
  struct stat st;
  ATF_REQUIRE(::stat((s.host + "/rc.conf").c_str(), &st) == 0);
  ATF_REQUIRE((st.st_mode & 0777) != 0777);
  // the message names the link
  try { FsBeneath::appendFile(s.tree, "/etc/rc.conf", "x"); ATF_FAIL("no throw"); }
  catch (const std::exception &e) { ATF_REQUIRE(std::string(e.what()).find("symbolic link") != std::string::npos); }
  // a link deeper down too
  ATF_REQUIRE(::mkdir((s.tree + "/var").c_str(), 0755) == 0);
  ATF_REQUIRE(::symlink(s.host.c_str(), (s.tree + "/var/cron").c_str()) == 0);
  ATF_REQUIRE(throws([&] { FsBeneath::writeFile(s.tree, "/var/cron/tabs", "x"); }));
}

ATF_TEST_CASE_WITHOUT_HEAD(symlinked_leaf_refused_or_replaced);
ATF_TEST_CASE_BODY(symlinked_leaf_refused_or_replaced) {
  Scratch s;
  const std::string leaf = s.tree + "/etc/hostid";
  ATF_REQUIRE(::symlink((s.host + "/rc.conf").c_str(), leaf.c_str()) == 0);
  ATF_REQUIRE(throws([&] { FsBeneath::writeFile(s.tree, "/etc/hostid", "evil"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::appendFile(s.tree, "/etc/hostid", "evil"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::chown(s.tree, "/etc/hostid", ::getuid(), ::getgid()); }));
  ATF_REQUIRE(throws([&] { FsBeneath::copyOut(s.tree, "/etc/hostid", s.base + "/out"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::copyWithin(s.tree, "/etc/hostid", "/etc/copy", 0600); }));
  ATF_REQUIRE(!std::filesystem::exists(s.base + "/out"));
  ATF_REQUIRE(FsBeneath::exists(s.tree, "/etc/hostid"));        // the link itself exists
  ATF_REQUIRE(!FsBeneath::isDirectory(s.tree, "/etc/hostid"));
  // copyIn replaces the link, the link's target stays as it was
  Scratch::put(s.base + "/resolv", "nameserver 10.0.0.1\n");
  FsBeneath::copyIn(s.base + "/resolv", s.tree, "/etc/hostid", 0640);
  struct stat st;
  ATF_REQUIRE(::lstat(leaf.c_str(), &st) == 0);
  ATF_REQUIRE(S_ISREG(st.st_mode));
  ATF_REQUIRE_EQ((unsigned)(st.st_mode & 0777), 0640u);
  ATF_REQUIRE_EQ(Scratch::get(leaf), std::string("nameserver 10.0.0.1\n"));
  ATF_REQUIRE_EQ(Scratch::get(s.host + "/rc.conf"), std::string("host\n"));
  // FsBeneath::unlink removes a link, not its target
  ATF_REQUIRE(::symlink((s.host + "/rc.conf").c_str(), (s.tree + "/etc/l").c_str()) == 0);
  FsBeneath::unlink(s.tree, "/etc/l");
  ATF_REQUIRE(!FsBeneath::exists(s.tree, "/etc/l"));
  ATF_REQUIRE(std::filesystem::exists(s.host + "/rc.conf"));
}

ATF_TEST_CASE_WITHOUT_HEAD(non_regular_refused);
ATF_TEST_CASE_BODY(non_regular_refused) {
  Scratch s;
  ATF_REQUIRE(::mkfifo((s.tree + "/etc/fifo").c_str(), 0644) == 0);
  // no reader: must fail, not block
  ATF_REQUIRE(throws([&] { FsBeneath::writeFile(s.tree, "/etc/fifo", "x"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::appendFile(s.tree, "/etc/fifo", "x"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::copyOut(s.tree, "/etc/fifo", s.base + "/out"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::writeFile(s.tree, "/etc", "x"); }));     // a directory
  ATF_REQUIRE(throws([&] { FsBeneath::unlink(s.tree, "/etc"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::copyIn(s.host + "/rc.conf", s.tree, "/etc", 0644); }));
  ATF_REQUIRE(FsBeneath::isDirectory(s.tree, "/etc"));
  ATF_REQUIRE(throws([&] { FsBeneath::copyIn(s.host, s.tree, "/etc/x", 0644); }));  // source not a file
}

ATF_TEST_CASE_WITHOUT_HEAD(copy_chmod_chown_mkdirs);
ATF_TEST_CASE_BODY(copy_chmod_chown_mkdirs) {
  Scratch s;
  ATF_REQUIRE(::mkdir((s.tree + "/root").c_str(), 0700) == 0);
  ATF_REQUIRE(::mkdir((s.tree + "/home").c_str(), 0755) == 0);
  ATF_REQUIRE(::mkdir((s.tree + "/home/u").c_str(), 0755) == 0);
  Scratch::put(s.tree + "/root/.Xauthority", "cookie");
  FsBeneath::copyWithin(s.tree, "/root/.Xauthority", "/home/u/.Xauthority", 0600, ::getuid(), ::getgid());
  ATF_REQUIRE_EQ(Scratch::get(s.tree + "/home/u/.Xauthority"), std::string("cookie"));
  struct stat st;
  ATF_REQUIRE(::stat((s.tree + "/home/u/.Xauthority").c_str(), &st) == 0);
  ATF_REQUIRE_EQ((unsigned)(st.st_mode & 0777), 0600u);
  FsBeneath::chmod(s.tree, "/home/u/.Xauthority", 0640);
  ATF_REQUIRE(::stat((s.tree + "/home/u/.Xauthority").c_str(), &st) == 0);
  ATF_REQUIRE_EQ((unsigned)(st.st_mode & 0777), 0640u);
  FsBeneath::chown(s.tree, "/home/u/.Xauthority", ::getuid(), ::getgid());
  FsBeneath::chmod(s.tree, "/home/u", 0750);                    // a directory too
  ATF_REQUIRE(::stat((s.tree + "/home/u").c_str(), &st) == 0);
  ATF_REQUIRE_EQ((unsigned)(st.st_mode & 0777), 0750u);
  FsBeneath::copyOut(s.tree, "/home/u/.Xauthority", s.base + "/out");
  ATF_REQUIRE_EQ(Scratch::get(s.base + "/out"), std::string("cookie"));
  FsBeneath::unlink(s.tree, "/root/.Xauthority");
  ATF_REQUIRE(!FsBeneath::exists(s.tree, "/root/.Xauthority"));
  ATF_REQUIRE(!FsBeneath::exists(s.tree, "/no/such/dir/file"));
  FsBeneath::mkdirs(s.tree, "/usr/local/etc/unbound", 0755);
  ATF_REQUIRE(FsBeneath::isDirectory(s.tree, "/usr/local/etc/unbound"));
  FsBeneath::mkdirs(s.tree, "/usr/local/etc/unbound", 0755);    // already there
  Scratch::put(s.tree + "/usr/file", "");
  ATF_REQUIRE(throws([&] { FsBeneath::mkdirs(s.tree, "/usr/file/x", 0755); }));
}

// 1.1.77: mount targets, the socat directory, files/share links.
ATF_TEST_CASE_WITHOUT_HEAD(touch_and_open_directory);
ATF_TEST_CASE_BODY(touch_and_open_directory) {
  Scratch s;
  FsBeneath::mkdirs(s.tree, "/tmp/wayland", 0700);
  FsBeneath::touch(s.tree, "/tmp/wayland/pipewire-0");
  struct stat st;
  ATF_REQUIRE(::lstat((s.tree + "/tmp/wayland/pipewire-0").c_str(), &st) == 0);
  ATF_REQUIRE(S_ISREG(st.st_mode));
  ATF_REQUIRE_EQ(st.st_size, (off_t)0);
  Scratch::put(s.tree + "/tmp/wayland/kept", "data");
  FsBeneath::touch(s.tree, "/tmp/wayland/kept");                  // left as it is
  ATF_REQUIRE_EQ(Scratch::get(s.tree + "/tmp/wayland/kept"), std::string("data"));
  // a planted link at the target (-> a host file) or on the way
  ATF_REQUIRE(::symlink((s.host + "/rc.conf").c_str(), (s.tree + "/tmp/wayland/pulse").c_str()) == 0);
  ATF_REQUIRE(throws([&] { FsBeneath::touch(s.tree, "/tmp/wayland/pulse"); }));
  ATF_REQUIRE(::symlink(s.host.c_str(), (s.tree + "/tmp/x11").c_str()) == 0);
  ATF_REQUIRE(throws([&] { FsBeneath::touch(s.tree, "/tmp/x11/X0"); }));
  ATF_REQUIRE(!std::filesystem::exists(s.host + "/X0"));
  ATF_REQUIRE(throws([&] { FsBeneath::touch(s.tree, "/tmp"); }));   // a directory
  // openDirectory: the directory itself, root for "" / "/", links refused
  int fd = FsBeneath::openDirectory(s.tree, "/tmp/wayland");
  ATF_REQUIRE(fd >= 0);
  ATF_REQUIRE(::fstatat(fd, "kept", &st, AT_SYMLINK_NOFOLLOW) == 0);
  ::close(fd);
  fd = FsBeneath::openDirectory(s.tree, "/");
  ATF_REQUIRE(::fstatat(fd, "tmp", &st, AT_SYMLINK_NOFOLLOW) == 0);
  ::close(fd);
  fd = FsBeneath::openDirectory(s.tree, "");
  ::close(fd);
  ATF_REQUIRE(throws([&] { FsBeneath::openDirectory(s.tree, "/tmp/x11"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::openDirectory(s.tree, "/tmp/wayland/kept"); }));
  ATF_REQUIRE(throws([&] { FsBeneath::openDirectory(s.tree, "/tmp/../.."); }));
}

ATF_TEST_CASE_WITHOUT_HEAD(share_links);
ATF_TEST_CASE_BODY(share_links) {
  Scratch s;
  struct stat st, ht;
  ATF_REQUIRE(::stat(s.host.c_str(), &ht) == 0);
  ATF_REQUIRE(FsBeneath::parentDevice(s.tree, "/etc/new") == ht.st_dev);   // same scratch fs
  ATF_REQUIRE(throws([&] { FsBeneath::parentDevice(s.tree, "/nodir/x"); }));
  // host -> jail
  Scratch::put(s.host + "/app.conf", "conf");
  FsBeneath::linkIn(s.host + "/app.conf", s.tree, "/etc/app.conf");
  ATF_REQUIRE(::stat((s.tree + "/etc/app.conf").c_str(), &st) == 0);
  ATF_REQUIRE(::stat((s.host + "/app.conf").c_str(), &ht) == 0);
  ATF_REQUIRE(st.st_ino == ht.st_ino);
  ATF_REQUIRE(throws([&] { FsBeneath::linkIn(s.host + "/app.conf", s.tree, "/etc/app.conf"); }));   // exists
  // a host-side symlink source is followed (a dotfile linked into a repo)
  ATF_REQUIRE(::symlink((s.host + "/app.conf").c_str(), (s.host + "/dot").c_str()) == 0);
  FsBeneath::linkIn(s.host + "/dot", s.tree, "/etc/dot");
  ATF_REQUIRE(::lstat((s.tree + "/etc/dot").c_str(), &st) == 0);
  ATF_REQUIRE(S_ISREG(st.st_mode));
  // ... but not a link on the jail's side
  std::filesystem::create_directory(s.tree + "/var");
  ATF_REQUIRE(::symlink(s.host.c_str(), (s.tree + "/var/db").c_str()) == 0);
  ATF_REQUIRE(throws([&] { FsBeneath::linkIn(s.host + "/app.conf", s.tree, "/var/db/x"); }));
  ATF_REQUIRE(!std::filesystem::exists(s.host + "/x"));
  // jail -> host: a regular file only
  Scratch::put(s.tree + "/etc/made-in-jail", "j");
  FsBeneath::linkOut(s.tree, "/etc/made-in-jail", s.base + "/out");
  ATF_REQUIRE_EQ(Scratch::get(s.base + "/out"), std::string("j"));
  ATF_REQUIRE(::symlink((s.host + "/rc.conf").c_str(), (s.tree + "/etc/evil").c_str()) == 0);
  ATF_REQUIRE(throws([&] { FsBeneath::linkOut(s.tree, "/etc/evil", s.base + "/out2"); }));
  ATF_REQUIRE(!std::filesystem::exists(s.base + "/out2"));
  ATF_REQUIRE(throws([&] { FsBeneath::linkOut(s.tree, "/etc", s.base + "/out3"); }));
}

// 1.1.77: `crate import`'s output — a new file only
ATF_TEST_CASE_WITHOUT_HEAD(copy_to_new_file);
ATF_TEST_CASE_BODY(copy_to_new_file) {
  Scratch s;
  Scratch::put(s.host + "/a.txz", "archive");
  FsBeneath::copyToNewFile(s.host + "/a.txz", s.base + "/a.crate", 0644);
  ATF_REQUIRE_EQ(Scratch::get(s.base + "/a.crate"), std::string("archive"));
  // an existing file is not overwritten
  ATF_REQUIRE(throws([&] { FsBeneath::copyToNewFile(s.host + "/rc.conf", s.base + "/a.crate", 0644); }));
  ATF_REQUIRE_EQ(Scratch::get(s.base + "/a.crate"), std::string("archive"));
  // a dangling symlink planted at the output name is not written through
  ATF_REQUIRE(::symlink((s.host + "/victim").c_str(), (s.base + "/b.crate").c_str()) == 0);
  ATF_REQUIRE(throws([&] { FsBeneath::copyToNewFile(s.host + "/a.txz", s.base + "/b.crate", 0644); }));
  ATF_REQUIRE(!std::filesystem::exists(s.host + "/victim"));
  // nor a symlink to an existing file
  ATF_REQUIRE(::symlink((s.host + "/rc.conf").c_str(), (s.base + "/c.crate").c_str()) == 0);
  ATF_REQUIRE(throws([&] { FsBeneath::copyToNewFile(s.host + "/a.txz", s.base + "/c.crate", 0644); }));
  ATF_REQUIRE_EQ(Scratch::get(s.host + "/rc.conf"), std::string("host\n"));
  // a missing source leaves nothing behind
  ATF_REQUIRE(throws([&] { FsBeneath::copyToNewFile(s.host + "/nope", s.base + "/d.crate", 0644); }));
  ATF_REQUIRE(!std::filesystem::exists(s.base + "/d.crate"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, split_relative);
  ATF_ADD_TEST_CASE(tcs, write_and_append);
  ATF_ADD_TEST_CASE(tcs, symlinked_directory_refused);
  ATF_ADD_TEST_CASE(tcs, symlinked_leaf_refused_or_replaced);
  ATF_ADD_TEST_CASE(tcs, non_regular_refused);
  ATF_ADD_TEST_CASE(tcs, copy_chmod_chown_mkdirs);
  ATF_ADD_TEST_CASE(tcs, touch_and_open_directory);
  ATF_ADD_TEST_CASE(tcs, share_links);
  ATF_ADD_TEST_CASE(tcs, copy_to_new_file);
}
