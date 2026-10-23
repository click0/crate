// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.60: `crate profile-from-trace` — truss(1) line parsing, summary,
// spec generation (TracePure). Lines follow FreeBSD 14 truss -f output.

#include "trace_pure.h"

#include <atf-c++.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace TracePure;

static bool has(const std::vector<std::string> &v, const std::string &s) {
  return std::find(v.begin(), v.end(), s) != v.end();
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_open_variants);
ATF_TEST_CASE_BODY(parse_open_variants) {
  Event e;
  ATF_REQUIRE(parseLine(" 1234: open(\"/etc/libmap.conf\",O_RDONLY|O_CLOEXEC) = 3 (0x3)", e));
  ATF_REQUIRE(e.kind == Event::Kind::Open);
  ATF_REQUIRE_EQ(e.pid, 1234);
  ATF_REQUIRE_EQ(e.path, "/etc/libmap.conf");
  ATF_REQUIRE(!e.write);
  ATF_REQUIRE(!e.failed);

  ATF_REQUIRE(parseLine("1234: openat(AT_FDCWD,\"/home/alice/Downloads/a.pdf\",O_WRONLY|O_CREAT|O_TRUNC,0644) = 7 (0x7)", e));
  ATF_REQUIRE(e.write);
  ATF_REQUIRE_EQ(e.path, "/home/alice/Downloads/a.pdf");

  ATF_REQUIRE(parseLine("1234: openat(AT_FDCWD,\"/nonexistent\",O_RDONLY,00) ERR#2 'No such file or directory'", e));
  ATF_REQUIRE(e.failed);

  // no pid prefix, timestamp prefix, pid+tid prefix
  ATF_REQUIRE(parseLine("open(\"/x\",O_RDONLY) = 3 (0x3)", e));
  ATF_REQUIRE_EQ(e.pid, 0);
  ATF_REQUIRE(parseLine("1700000000.123456789  1234: open(\"/y\",O_RDWR) = 3 (0x3)", e));
  ATF_REQUIRE_EQ(e.path, "/y");
  ATF_REQUIRE(e.write);
  ATF_REQUIRE(parseLine(" 1234 100123: open(\"/z\",O_RDONLY) = 3 (0x3)", e));
  ATF_REQUIRE_EQ(e.pid, 1234);
  ATF_REQUIRE_EQ(e.path, "/z");

  // escapes and a parenthesis inside the string
  ATF_REQUIRE(parseLine("1: open(\"/tmp/a (1)\\\"q\\\"\\n\",O_RDONLY) = 3 (0x3)", e));
  ATF_REQUIRE_EQ(e.path, "/tmp/a (1)\"q\"\n");

  // uninteresting lines
  ATF_REQUIRE(!parseLine("1234: <new process>", e));
  ATF_REQUIRE(!parseLine("1234: process exit, rval = 0", e));
  ATF_REQUIRE(!parseLine("1234: SIGNAL 20 (SIGCHLD) code=CLD_EXITED pid=1235 uid=1000 status=0", e));
  ATF_REQUIRE(!parseLine("1234: mmap(0x0,4096,PROT_READ,MAP_PRIVATE,-1,0x0) = 34366 (0x8000)", e));
  ATF_REQUIRE(!parseLine("", e));
  ATF_REQUIRE(!parseLine("garbage without parens", e));
  ATF_REQUIRE(!parseLine("1234: open(\"/unterminated,O_RDONLY) = 3", e));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_exec_stat_sockets);
ATF_TEST_CASE_BODY(parse_exec_stat_sockets) {
  Event e;
  ATF_REQUIRE(parseLine("1234: execve(\"/usr/local/bin/firefox\",[ \"firefox\", \"--new-window\", \"https://x\" ],0x820a3b000) EJUSTRETURN", e));
  ATF_REQUIRE(e.kind == Event::Kind::Exec);
  ATF_REQUIRE_EQ(e.path, "/usr/local/bin/firefox");
  ATF_REQUIRE_EQ(e.argv.size(), 3u);
  ATF_REQUIRE_EQ(e.argv[1], "--new-window");
  ATF_REQUIRE(!e.failed);
  ATF_REQUIRE(parseLine("1234: execve(\"/usr/local/bin/missing\",[ \"missing\" ],0x1) ERR#2 'No such file or directory'", e));
  ATF_REQUIRE(e.failed);

  ATF_REQUIRE(parseLine("1234: fstatat(AT_FDCWD,\"/home/alice/.mozilla\",{ mode=drwx------ ,inode=4,size=5,blksize=32768 },0x0) = 0 (0x0)", e));
  ATF_REQUIRE(e.kind == Event::Kind::Stat);
  ATF_REQUIRE_EQ(e.path, "/home/alice/.mozilla");

  ATF_REQUIRE(parseLine("1234: socket(PF_INET,SOCK_STREAM|SOCK_CLOEXEC,6) = 5 (0x5)", e));
  ATF_REQUIRE(e.kind == Event::Kind::Socket);
  ATF_REQUIRE_EQ(e.fd, 5);
  ATF_REQUIRE_EQ(e.family, "inet");
  ATF_REQUIRE(!e.datagram);
  ATF_REQUIRE(parseLine("1234: socket(PF_INET6,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,17) = 6 (0x6)", e));
  ATF_REQUIRE_EQ(e.family, "inet6");
  ATF_REQUIRE(e.datagram);
  ATF_REQUIRE(parseLine("1234: socket(PF_LOCAL,SOCK_STREAM,0) = 4 (0x4)", e));
  ATF_REQUIRE_EQ(e.family, "unix");

  ATF_REQUIRE(parseLine("1234: connect(5,{ AF_INET 93.184.216.34:443 },16) = 0 (0x0)", e));
  ATF_REQUIRE(e.kind == Event::Kind::Connect);
  ATF_REQUIRE_EQ(e.fd, 5);
  ATF_REQUIRE_EQ(e.host, "93.184.216.34");
  ATF_REQUIRE_EQ(e.port, 443u);
  ATF_REQUIRE(parseLine("1234: connect(5,{ AF_INET6 [2606:4700::1111]:443 },28) ERR#36 'Operation now in progress'", e));
  ATF_REQUIRE_EQ(e.family, "inet6");
  ATF_REQUIRE_EQ(e.host, "2606:4700::1111");
  ATF_REQUIRE_EQ(e.port, 443u);
  ATF_REQUIRE(!e.failed);   // in progress = will connect
  ATF_REQUIRE(parseLine("1234: connect(5,{ AF_INET 10.0.0.1:80 },16) ERR#61 'Connection refused'", e));
  ATF_REQUIRE(e.failed);
  ATF_REQUIRE(parseLine("1234: connect(4,{ AF_UNIX \"/tmp/.X11-unix/X0\" },110) = 0 (0x0)", e));
  ATF_REQUIRE_EQ(e.family, "unix");
  ATF_REQUIRE_EQ(e.path, "/tmp/.X11-unix/X0");

  ATF_REQUIRE(parseLine("1234: bind(6,{ AF_INET 0.0.0.0:8080 },16) = 0 (0x0)", e));
  ATF_REQUIRE(e.kind == Event::Kind::Bind);
  ATF_REQUIRE_EQ(e.port, 8080u);
  ATF_REQUIRE(parseLine("1234: listen(6,128) = 0 (0x0)", e));
  ATF_REQUIRE(e.kind == Event::Kind::Listen);
  ATF_REQUIRE_EQ(e.fd, 6);
  ATF_REQUIRE(parseLine("1234: sendto(7,\"\\M-\\^G\\^A\\0\\0\\0\\^A\",33,0,{ AF_INET 1.1.1.1:53 },16) = 33 (0x21)", e));
  ATF_REQUIRE(e.kind == Event::Kind::Sendto);
  ATF_REQUIRE_EQ(e.host, "1.1.1.1");
  ATF_REQUIRE_EQ(e.port, 53u);
  // connected-UDP sendto has no address: not an event
  ATF_REQUIRE(!parseLine("1234: sendto(7,\"x\",1,0,NULL,0) = 1 (0x1)", e));
}

static std::vector<std::string> firefoxTrace() {
  return {
    " 1000: execve(\"/usr/local/bin/firefox\",[ \"firefox\", \"--private-window\" ],0x1) EJUSTRETURN",
    " 1000: open(\"/etc/libmap.conf\",O_RDONLY|O_CLOEXEC) = 3 (0x3)",
    " 1000: openat(AT_FDCWD,\"/usr/local/lib/firefox/libxul.so\",O_RDONLY|O_CLOEXEC,00) = 3 (0x3)",
    " 1000: openat(AT_FDCWD,\"/usr/local/lib/libnspr4.so\",O_RDONLY|O_CLOEXEC,00) = 3 (0x3)",
    " 1000: openat(AT_FDCWD,\"/usr/local/lib/libunowned.so\",O_RDONLY,00) = 3 (0x3)",
    " 1000: openat(AT_FDCWD,\"/usr/local/etc/fonts/fonts.conf\",O_RDONLY,00) = 3 (0x3)",
    " 1000: openat(AT_FDCWD,\"/etc/ssl/cert.pem\",O_RDONLY,00) = 3 (0x3)",
    " 1000: openat(AT_FDCWD,\"/home/alice/.mozilla/firefox/abc.default/places.sqlite\",O_RDWR|O_CREAT,0644) = 9 (0x9)",
    " 1000: openat(AT_FDCWD,\"/usr/home/alice/Downloads/report.pdf\",O_WRONLY|O_CREAT|O_TRUNC,0644) = 10 (0xa)",
    " 1000: openat(AT_FDCWD,\"/home/alice/.config/gtk-3.0/settings.ini\",O_RDONLY,00) = 11 (0xb)",
    " 1000: openat(AT_FDCWD,\"/home/alice/.local/share/applications/mimeinfo.cache\",O_RDONLY,00) = 12 (0xc)",
    " 1000: openat(AT_FDCWD,\"/home/alice/.cache/mozilla/x\",O_RDWR|O_CREAT,0644) = 13 (0xd)",
    " 1000: openat(AT_FDCWD,\"/home/alice/.Xauthority\",O_RDONLY,00) = 14 (0xe)",
    " 1000: openat(AT_FDCWD,\"/home/alice/notes.txt\",O_RDONLY,00) = 15 (0xf)",
    " 1000: openat(AT_FDCWD,\"/mnt/data/videos/a.mkv\",O_RDONLY,00) = 16 (0x10)",
    " 1000: openat(AT_FDCWD,\"/srv/shared/docs/x.odt\",O_RDONLY,00) = 17 (0x11)",
    " 1000: openat(AT_FDCWD,\"/srv/shared/docs/sub/y.odt\",O_RDONLY,00) = 18 (0x12)",
    " 1000: openat(AT_FDCWD,\"/home/alice/Secret/key\",O_RDONLY,00) ERR#13 'Permission denied'",
    " 1000: openat(AT_FDCWD,\"/dev/dri/renderD128\",O_RDWR|O_CLOEXEC,00) = 19 (0x13)",
    " 1000: openat(AT_FDCWD,\"/dev/dsp\",O_WRONLY,00) = 20 (0x14)",
    " 1000: socket(PF_LOCAL,SOCK_STREAM|SOCK_CLOEXEC,0) = 4 (0x4)",
    " 1000: connect(4,{ AF_UNIX \"/tmp/.X11-unix/X0\" },110) = 0 (0x0)",
    " 1000: socket(PF_LOCAL,SOCK_STREAM|SOCK_CLOEXEC,0) = 21 (0x15)",
    " 1000: connect(21,{ AF_UNIX \"/var/run/user/1001/bus\" },110) = 0 (0x0)",
    " 1000: socket(PF_INET,SOCK_DGRAM|SOCK_CLOEXEC,17) = 22 (0x16)",
    " 1000: sendto(22,\"...\",33,0,{ AF_INET 192.168.1.1:53 },16) = 33 (0x21)",
    " 1000: socket(PF_INET,SOCK_STREAM|SOCK_CLOEXEC,6) = 23 (0x17)",
    " 1000: connect(23,{ AF_INET 93.184.216.34:443 },16) ERR#36 'Operation now in progress'",
    " 1000: socket(PF_INET6,SOCK_STREAM|SOCK_CLOEXEC,6) = 24 (0x18)",
    " 1000: connect(24,{ AF_INET6 [2606:4700::1111]:443 },28) = 0 (0x0)",
    " 1000: connect(23,{ AF_INET 10.1.2.3:8443 },16) ERR#61 'Connection refused'",
    " 1001: <new process>",
    " 1001: execve(\"/bin/sh\",[ \"sh\", \"-c\", \"xdg-open x\" ],0x1) EJUSTRETURN",
    " 1001: execve(\"/usr/local/bin/xdg-open\",[ \"xdg-open\", \"x\" ],0x1) EJUSTRETURN",
    " 1000: process exit, rval = 0",
  };
}

ATF_TEST_CASE_WITHOUT_HEAD(summarize_firefox_like_trace);
ATF_TEST_CASE_BODY(summarize_firefox_like_trace) {
  auto s = summarize(firefoxTrace());
  ATF_REQUIRE(s.parsed > 20);
  ATF_REQUIRE_EQ(s.execs.size(), 3u);
  ATF_REQUIRE_EQ(s.execs[0], "/usr/local/bin/firefox");
  ATF_REQUIRE_EQ(s.execArgv[0].size(), 2u);
  ATF_REQUIRE(s.readPaths.count("/etc/libmap.conf"));
  ATF_REQUIRE(s.writePaths.count("/usr/home/alice/Downloads/report.pdf"));
  ATF_REQUIRE(!s.readPaths.count("/home/alice/Secret/key"));          // failed open
  ATF_REQUIRE(s.unixSockets.count("/tmp/.X11-unix/X0"));
  ATF_REQUIRE_EQ(s.outbound.size(), 3u);                              // dns udp, 2 https; refused one dropped
  bool sawUdpDns = false, sawV6 = false;
  for (auto &e : s.outbound) {
    if (e.port == 53 && e.udp && e.host == "192.168.1.1") sawUdpDns = true;
    if (e.host == "2606:4700::1111" && !e.udp) sawV6 = true;
    ATF_REQUIRE(e.host != "10.1.2.3");
  }
  ATF_REQUIRE(sawUdpDns);
  ATF_REQUIRE(sawV6);
  ATF_REQUIRE(s.listening.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(generate_firefox_like_spec);
ATF_TEST_CASE_BODY(generate_firefox_like_spec) {
  auto s = summarize(firefoxTrace());
  Input in;
  in.home = "/home/alice";
  in.pkgOwner = {
    {"/usr/local/bin/firefox", "firefox"},
    {"/usr/local/lib/firefox/libxul.so", "firefox"},
    {"/usr/local/lib/libnspr4.so", "nspr"},
    {"/usr/local/bin/xdg-open", "xdg-utils"},
    {"/usr/local/etc/fonts/fonts.conf", "fontconfig"},
  };
  auto g = generate(s, in);

  ATF_REQUIRE_EQ(g.command.size(), 2u);
  ATF_REQUIRE_EQ(g.command[0], "/usr/local/bin/firefox");
  ATF_REQUIRE_EQ(g.command[1], "--private-window");
  ATF_REQUIRE(has(g.pkgs, "firefox"));
  ATF_REQUIRE(has(g.pkgs, "xdg-utils"));
  ATF_REQUIRE(!has(g.pkgs, "nspr"));
  ATF_REQUIRE(has(g.otherPkgs, "nspr"));
  ATF_REQUIRE(has(g.otherPkgs, "fontconfig"));

  ATF_REQUIRE(has(g.dirShares, "$HOME/Downloads"));                   // via /usr/home spelling
  ATF_REQUIRE(has(g.dirShares, "/mnt/data/videos") == false);          // /mnt is ignored (mount it deliberately)
  ATF_REQUIRE(has(g.dirShares, "/srv/shared/docs"));                   // collapsed to the shortest ancestor
  ATF_REQUIRE(!has(g.dirShares, "/srv/shared/docs/sub"));
  ATF_REQUIRE(has(g.stateDirShares, "$HOME/.mozilla"));
  ATF_REQUIRE(has(g.stateDirShares, "$HOME/.config/gtk-3.0"));
  ATF_REQUIRE(has(g.stateDirShares, "$HOME/.local/share/applications"));
  ATF_REQUIRE(!has(g.stateDirShares, "$HOME/.cache"));
  ATF_REQUIRE(has(g.fileShares, "$HOME/notes.txt"));
  ATF_REQUIRE(!has(g.fileShares, "$HOME/.Xauthority"));
  for (auto &d : g.dirShares) ATF_REQUIRE(d.find("Secret") == std::string::npos);

  ATF_REQUIRE(g.x11);
  ATF_REQUIRE(g.gl);
  ATF_REQUIRE(!g.video);
  ATF_REQUIRE(g.sslCerts);
  ATF_REQUIRE(g.dbusSession);
  ATF_REQUIRE(!g.dbusSystem);
  ATF_REQUIRE(g.net);
  ATF_REQUIRE_EQ(g.outbound.size(), 2u);
  ATF_REQUIRE_EQ(g.outbound[0], "wan");
  ATF_REQUIRE_EQ(g.outbound[1], "dns");
  ATF_REQUIRE(g.inboundTcp.empty());
  ATF_REQUIRE(has(g.outboundSeen, "93.184.216.34:443/tcp"));
  ATF_REQUIRE(has(g.outboundSeen, "[2606:4700::1111]:443/tcp"));
  ATF_REQUIRE(has(g.outboundSeen, "192.168.1.1:53/udp"));
  bool soundNote = false, unownedNote = false, cacheNote = false;
  for (auto &n : g.notes) {
    if (n.find("sound") != std::string::npos) soundNote = true;
    if (n.find("libunowned.so") != std::string::npos) unownedNote = true;
    if (n.find(".cache") != std::string::npos) cacheNote = true;
  }
  ATF_REQUIRE(soundNote);
  ATF_REQUIRE(unownedNote);
  ATF_REQUIRE(cacheNote);

  auto yaml = renderSpec(g, "1.1.60");
  ATF_REQUIRE(yaml.find("pkg:\n    install:\n        - firefox\n") != std::string::npos);
  ATF_REQUIRE(yaml.find("command: \"/usr/local/bin/firefox --private-window\"") != std::string::npos);
  ATF_REQUIRE(yaml.find("- [$HOME/Downloads, $HOME/Downloads]") != std::string::npos);
  ATF_REQUIRE(yaml.find("- [$HOME/.mozilla, $HOME/.mozilla]") != std::string::npos);
  ATF_REQUIRE(yaml.find("files:\n    share:\n        - [$HOME/notes.txt, $HOME/notes.txt]") != std::string::npos);
  ATF_REQUIRE(yaml.find("options:\n    net:\n        outbound: [wan, dns]\n    x11:\n    gl:\n    ssl-certs:\n") != std::string::npos);
  ATF_REQUIRE(yaml.find("dbus:\n    session: true\n") != std::string::npos);
  ATF_REQUIRE(yaml.find("# outbound destinations seen:") != std::string::npos);
  ATF_REQUIRE(yaml.find("Secret") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(generate_server_and_edge_cases);
ATF_TEST_CASE_BODY(generate_server_and_edge_cases) {
  std::vector<std::string> trace = {
    "execve(\"/usr/local/sbin/nginx\",[ \"nginx\", \"-g\", \"daemon off;\" ],0x1) EJUSTRETURN",
    "socket(PF_INET,SOCK_STREAM,6) = 5 (0x5)",
    "bind(5,{ AF_INET 0.0.0.0:8080 },16) = 0 (0x0)",
    "listen(5,511) = 0 (0x0)",
    "socket(PF_INET,SOCK_DGRAM,17) = 6 (0x6)",
    "bind(6,{ AF_INET 0.0.0.0:5353 },16) = 0 (0x0)",
    "socket(PF_INET,SOCK_STREAM,6) = 7 (0x7)",
    "bind(7,{ AF_INET 0.0.0.0:0 },16) = 0 (0x0)",   // ephemeral: not inbound
    "listen(7,1) = 0 (0x0)",
    "socket(PF_INET,SOCK_STREAM,6) = 8 (0x8)",
    "connect(8,{ AF_INET 127.0.0.1:5432 },16) = 0 (0x0)",
    "connect(8,{ AF_INET 10.0.0.9:6379 },16) = 0 (0x0)",
    "socket(PF_LOCAL,SOCK_STREAM,0) = 9 (0x9)",
    "connect(9,{ AF_UNIX \"/var/run/dbus/system_bus_socket\" },110) = 0 (0x0)",
    "openat(AT_FDCWD,\"/usr/local/www/site/index.html\",O_RDONLY,00) = 10 (0xa)",
    "openat(AT_FDCWD,\"/var/log/nginx/access.log\",O_WRONLY|O_APPEND,00) = 11 (0xb)",
    "openat(AT_FDCWD,\"/dev/video0\",O_RDWR,00) = 12 (0xc)",
    "openat(AT_FDCWD,\"relative/path\",O_RDONLY,00) = 13 (0xd)",
  };
  auto s = summarize(trace);
  ATF_REQUIRE_EQ(s.listening.size(), 2u);
  ATF_REQUIRE(!s.readPaths.count("relative/path"));

  Input in;
  in.home = "/root";
  in.command = {"nginx", "-g", "daemon off;"};   // the operator's spelling wins
  auto g = generate(s, in);
  ATF_REQUIRE_EQ(g.command.size(), 3u);
  ATF_REQUIRE_EQ(g.command[0], "nginx");
  ATF_REQUIRE(g.pkgs.empty());                     // no pkg info given
  ATF_REQUIRE_EQ(g.inboundTcp.size(), 1u);
  ATF_REQUIRE_EQ(g.inboundTcp[0], 8080u);
  ATF_REQUIRE_EQ(g.inboundUdp.size(), 1u);
  ATF_REQUIRE_EQ(g.inboundUdp[0], 5353u);
  ATF_REQUIRE_EQ(g.outbound.size(), 2u);
  ATF_REQUIRE_EQ(g.outbound[0], "lan");
  ATF_REQUIRE_EQ(g.outbound[1], "host");
  ATF_REQUIRE(g.dbusSystem);
  ATF_REQUIRE(g.video);
  ATF_REQUIRE(!g.x11);
  ATF_REQUIRE(g.dirShares.empty());                // /usr/local and /var/log are ignored
  bool unowned = false;
  for (auto &n : g.notes) if (n.find("/usr/local/www/site/index.html") != std::string::npos) unowned = true;
  ATF_REQUIRE(unowned);

  auto yaml = renderSpec(g, "1.1.60");
  ATF_REQUIRE(yaml.find("command: \"nginx -g daemon off;\"") != std::string::npos);
  ATF_REQUIRE(yaml.find("        outbound: [lan, host]\n        inbound-tcp:\n            8080: 8080\n        inbound-udp:\n            5353: 5353\n    video:\n") != std::string::npos);
  ATF_REQUIRE(yaml.find("dbus:\n    system: true\n") != std::string::npos);
  ATF_REQUIRE(yaml.find("pkg:") == std::string::npos);

  // all four classes and nothing inbound: the plain `net` option, list form
  std::vector<std::string> t2 = {
    "execve(\"/usr/bin/fetch\",[ \"fetch\" ],0x1) EJUSTRETURN",
    "socket(PF_INET,SOCK_STREAM,6) = 3 (0x3)",
    "connect(3,{ AF_INET 1.1.1.1:53 },16) = 0 (0x0)",
    "connect(3,{ AF_INET 127.0.0.1:80 },16) = 0 (0x0)",
    "connect(3,{ AF_INET 172.20.0.5:80 },16) = 0 (0x0)",
    "connect(3,{ AF_INET 203.0.113.7:443 },16) = 0 (0x0)",
    "openat(AT_FDCWD,\"/usr/local/share/certs/ca-root-nss.crt\",O_RDONLY,00) = 4 (0x4)",
  };
  auto g2 = generate(summarize(t2), Input{"/home/bob", {}, {}});
  ATF_REQUIRE_EQ(g2.outbound.size(), 4u);
  auto y2 = renderSpec(g2, "1.1.60");
  ATF_REQUIRE(y2.find("options:\n    - net\n    - ssl-certs\n") != std::string::npos);
  ATF_REQUIRE(y2.find("command: /usr/bin/fetch\n") != std::string::npos);

  // an empty trace: no command, no options, a note
  auto g3 = generate(summarize({"1: <new process>"}), Input{"/home/bob", {}, {}});
  ATF_REQUIRE(g3.command.empty());
  ATF_REQUIRE(!g3.net);
  bool noExec = false;
  for (auto &n : g3.notes) if (n.find("no execve") != std::string::npos) noExec = true;
  ATF_REQUIRE(noExec);
  auto y3 = renderSpec(g3, "1.1.60");
  ATF_REQUIRE(y3.find("options:") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(helpers);
ATF_TEST_CASE_BODY(helpers) {
  ATF_REQUIRE_EQ(pkgNameFromNameVersion("firefox-128.0,2"), "firefox");
  ATF_REQUIRE_EQ(pkgNameFromNameVersion("py311-yaml-6.0.1_1"), "py311-yaml");
  ATF_REQUIRE_EQ(pkgNameFromNameVersion("gtk3-3.24.43"), "gtk3");
  ATF_REQUIRE_EQ(pkgNameFromNameVersion("noversion"), "noversion");

  auto m = parsePkgWhichOutput(
    "/usr/local/bin/firefox was installed by package firefox-128.0,2\n"
    "/usr/local/lib/libunowned.so was not found in the database\n"
    "/usr/local/lib/libnspr4.so was installed by package nspr-4.35\n"
    "pkg: some warning line\n");
  ATF_REQUIRE_EQ(m.size(), 2u);
  ATF_REQUIRE_EQ(m["/usr/local/bin/firefox"], "firefox");
  ATF_REQUIRE_EQ(m["/usr/local/lib/libnspr4.so"], "nspr");

  ATF_REQUIRE_EQ(classifyHost("1.1.1.1", 53), "dns");
  ATF_REQUIRE_EQ(classifyHost("127.0.0.1", 8080), "host");
  ATF_REQUIRE_EQ(classifyHost("::1", 80), "host");
  ATF_REQUIRE_EQ(classifyHost("10.2.3.4", 80), "lan");
  ATF_REQUIRE_EQ(classifyHost("172.31.0.1", 80), "lan");
  ATF_REQUIRE_EQ(classifyHost("172.32.0.1", 80), "wan");
  ATF_REQUIRE_EQ(classifyHost("192.168.0.1", 443), "lan");
  ATF_REQUIRE_EQ(classifyHost("fe80::1", 80), "lan");
  ATF_REQUIRE_EQ(classifyHost("fd00::1", 80), "lan");
  ATF_REQUIRE_EQ(classifyHost("::ffff:93.184.216.34", 443), "wan");
  ATF_REQUIRE_EQ(classifyHost("2606:4700::1111", 443), "wan");

  ATF_REQUIRE_EQ(homeRelative("/home/alice/Downloads/x", "/home/alice"), "$HOME/Downloads/x");
  ATF_REQUIRE_EQ(homeRelative("/usr/home/alice/Downloads/x", "/home/alice"), "$HOME/Downloads/x");
  ATF_REQUIRE_EQ(homeRelative("/home/alice", "/home/alice/"), "$HOME");
  ATF_REQUIRE_EQ(homeRelative("/home/alicex/y", "/home/alice"), "");
  ATF_REQUIRE_EQ(homeRelative("/etc/passwd", "/home/alice"), "");
  ATF_REQUIRE_EQ(homeRelative("/root/x", "/"), "");

  ATF_REQUIRE_EQ(yamlScalar("$HOME/Downloads"), "$HOME/Downloads");
  ATF_REQUIRE_EQ(yamlScalar("/usr/local/bin/firefox"), "/usr/local/bin/firefox");
  ATF_REQUIRE_EQ(yamlScalar("a b"), "\"a b\"");
  ATF_REQUIRE_EQ(yamlScalar("-x"), "\"-x\"");
  ATF_REQUIRE_EQ(yamlScalar("he said \"hi\""), "\"he said \\\"hi\\\"\"");
  ATF_REQUIRE_EQ(yamlScalar("true"), "\"true\"");
  ATF_REQUIRE_EQ(yamlScalar(""), "\"\"");
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, parse_open_variants);
  ATF_ADD_TEST_CASE(tcs, parse_exec_stat_sockets);
  ATF_ADD_TEST_CASE(tcs, summarize_firefox_like_trace);
  ATF_ADD_TEST_CASE(tcs, generate_firefox_like_spec);
  ATF_ADD_TEST_CASE(tcs, generate_server_and_edge_cases);
  ATF_ADD_TEST_CASE(tcs, helpers);
}
