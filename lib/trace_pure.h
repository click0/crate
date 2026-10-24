// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// 1.1.60: `crate profile-from-trace -- <cmd>` (TODO §17.3, firejail's
// --build / --trace). The program runs once under truss(1) on the host
// and the trace of what it opened, executed, connected to and listened
// on is turned into a MINIMAL spec draft: read/written directories under
// the home → dirs/share, exec'd /usr/local binaries → pkg/install (via
// `pkg which`), X11 / D-Bus sockets → the matching options, outbound
// destinations → options/net/outbound, listening sockets → inbound.
//
// Everything here is text in, text out — the FreeBSD truss(1) output
// format of 14.x/15.x — so it unit-tests on Linux with recorded lines.
// The runner (truss, pkg which, file I/O) is lib/trace.cpp.
//
// Recognised truss line shapes (optional "<pid>: ", "<pid> <tid>: " and
// "<sec>.<nsec> " prefixes are skipped):
//
//   open("/p",O_RDONLY|O_CLOEXEC) = 3 (0x3)
//   openat(AT_FDCWD,"/p",O_WRONLY|O_CREAT,0644) ERR#13 'Permission denied'
//   stat("/p",{ ... }) / fstatat(AT_FDCWD,"/p",...) / access / readlink
//   execve("/usr/local/bin/x",[ "x", "--flag" ],0x8...) EJUSTRETURN
//   socket(PF_INET,SOCK_STREAM|SOCK_CLOEXEC,6) = 5 (0x5)
//   connect(5,{ AF_INET 93.184.216.34:443 },16) = 0 (0x0)
//   connect(5,{ AF_INET6 [2606:4700::1111]:443 },28) ERR#36 'Operation now in progress'
//   connect(4,{ AF_UNIX "/tmp/.X11-unix/X0" },110) = 0 (0x0)
//   bind(6,{ AF_INET 0.0.0.0:8080 },16) = 0 (0x0)   +   listen(6,128) = 0 (0x0)
//   sendto(7,"...",33,0,{ AF_INET 1.1.1.1:53 },16) = 33 (0x21)
//

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace TracePure {

struct Event {
  enum class Kind { None, Open, Stat, Exec, Socket, Connect, Bind, Listen, Sendto };
  Kind kind = Kind::None;
  long pid = 0;                    // 0 when the line has no pid prefix
  int fd = -1;                     // Socket: the result; Connect/Bind/Listen/Sendto: the argument
  std::string path;                // Open/Stat/Exec; AF_UNIX address for Connect/Bind
  std::vector<std::string> argv;   // Exec
  bool write = false;              // Open with O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND
  bool failed = false;             // ERR# result (a non-blocking connect "in progress" counts as success)
  std::string family;              // "inet", "inet6", "unix", "other"
  bool datagram = false;           // Socket: SOCK_DGRAM
  std::string host;                // numeric address for inet/inet6
  unsigned port = 0;
};

// One truss line → Event. False for lines of no interest (signals,
// process start/exit, other syscalls) or that do not parse.
bool parseLine(const std::string &line, Event &out);

struct Endpoint {
  std::string host;
  unsigned port = 0;
  bool udp = false;
  bool operator<(const Endpoint &o) const {
    if (host != o.host) return host < o.host;
    if (port != o.port) return port < o.port;
    return udp < o.udp;
  }
};

struct Summary {
  std::vector<std::string> execs;                 // successful execve paths, first first, deduped
  std::vector<std::vector<std::string>> execArgv; // parallel to execs
  std::set<std::string> readPaths, writePaths;    // successful absolute opens
  std::set<std::string> probedPaths;              // successful stat/access (not used for shares)
  std::set<std::string> unixSockets;              // successful AF_UNIX connects
  std::set<Endpoint> outbound;                    // inet/inet6 connects (+ sendto for UDP)
  std::set<Endpoint> listening;                   // bind+listen (tcp), bind on a datagram socket (udp)
  unsigned lines = 0, parsed = 0;
};
Summary summarize(const std::vector<std::string> &lines);

struct Input {
  std::string home;                                 // the invoking user's home ("/home/alice")
  std::map<std::string, std::string> pkgOwner;      // /usr/local path → package name (from `pkg which`)
  std::vector<std::string> command;                 // the command as given on the CLI, if any
};

struct Generated {
  std::vector<std::string> command;        // run/command words
  std::vector<std::string> pkgs;           // packages owning executed files
  std::vector<std::string> otherPkgs;      // packages whose files were only read (a note)
  std::vector<std::string> dirShares;      // $HOME/... or absolute
  std::vector<std::string> stateDirShares; // $HOME/.config/x, $HOME/.mozilla, ...: app state
  std::vector<std::string> fileShares;
  bool x11 = false, gl = false, video = false, sslCerts = false;
  bool net = false;
  std::vector<std::string> outbound;       // subset of wan, lan, host, dns in that order
  std::vector<unsigned> inboundTcp, inboundUdp;
  bool dbusSystem = false, dbusSession = false;
  // 1.1.62: device classes seen (`devices:` block); gpu and video are
  // covered by the gl / video options
  bool devSound = false, devInput = false, devUsb = false;
  std::vector<std::string> outboundSeen;   // "93.184.216.34:443/tcp"
  std::vector<std::string> notes;          // things the operator must decide
};
Generated generate(const Summary &s, const Input &in);

// The spec draft as YAML text (4-space indentation, like examples/).
std::string renderSpec(const Generated &g, const std::string &crateVersion);

// --- helpers, exposed for tests ---

// "firefox-128.0,2" → "firefox"; "py311-yaml-6.0.1_1" → "py311-yaml".
std::string pkgNameFromNameVersion(const std::string &nv);
// `pkg which` output: "<path> was installed by package <name-version>" lines
// (other lines ignored) → path → package name.
std::map<std::string, std::string> parsePkgWhichOutput(const std::string &out);
// "dns" (port 53), "host" (loopback), "lan" (RFC 1918 / link-local / ULA), "wan".
std::string classifyHost(const std::string &host, unsigned port);
// "/home/alice/Downloads/x" → "$HOME/Downloads/x"; "" when not under home.
// Accepts the /usr/home spelling of a /home/<user> home.
std::string homeRelative(const std::string &path, const std::string &home);
// A YAML scalar: bare when it is plainly safe, double-quoted otherwise.
std::string yamlScalar(const std::string &s);

} // namespace TracePure
