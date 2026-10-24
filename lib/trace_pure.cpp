// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "trace_pure.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>

namespace TracePure {

// ---------------------------------------------------------------- strings

static bool startsWith(const std::string &s, const std::string &p) {
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

static bool isUnder(const std::string &path, const std::string &dir) {
  return path == dir
         || (path.size() > dir.size() && startsWith(path, dir) && path[dir.size()] == '/');
}

static std::string trim(const std::string &s) {
  size_t b = 0, e = s.size();
  while (b < e && std::isspace((unsigned char)s[b])) b++;
  while (e > b && std::isspace((unsigned char)s[e - 1])) e--;
  return s.substr(b, e - b);
}

static unsigned toUnsigned(const std::string &s) {
  return (unsigned)std::strtoul(s.c_str(), nullptr, 10);
}

static std::string dirname(const std::string &p) {
  auto k = p.rfind('/');
  if (k == std::string::npos || k == 0) return "/";
  return p.substr(0, k);
}

// A C-quoted string as truss prints it; `pos` at the opening quote, left
// after the closing one.
static bool unquote(const std::string &s, size_t &pos, std::string &out) {
  if (pos >= s.size() || s[pos] != '"') return false;
  out.clear();
  pos++;
  while (pos < s.size()) {
    char c = s[pos];
    if (c == '"') { pos++; return true; }
    if (c == '\\' && pos + 1 < s.size()) {
      char e = s[pos + 1];
      if (e >= '0' && e <= '7') {
        int v = 0, n = 0;
        pos++;
        while (n < 3 && pos < s.size() && s[pos] >= '0' && s[pos] <= '7') { v = v * 8 + (s[pos] - '0'); pos++; n++; }
        out += (char)v;
        continue;
      }
      switch (e) {
      case 'n': out += '\n'; break;
      case 't': out += '\t'; break;
      case 'r': out += '\r'; break;
      default:  out += e;    break;
      }
      pos += 2;
      continue;
    }
    out += c;
    pos++;
  }
  return false;   // unterminated
}

static std::string unquoteArg(const std::string &a) {
  size_t p = 0;
  std::string out;
  if (!a.empty() && a[0] == '"' && unquote(a, p, out)) return out;
  return a;
}

// Top-level comma split, quotes and {} [] () respected.
static std::vector<std::string> splitArgs(const std::string &s) {
  std::vector<std::string> out;
  std::string cur;
  int depth = 0;
  for (size_t i = 0; i < s.size(); i++) {
    char c = s[i];
    if (c == '"') {
      std::string tmp;
      size_t p = i;
      if (unquote(s, p, tmp)) { cur.append(s, i, p - i); i = p - 1; continue; }
    }
    if (c == '{' || c == '[' || c == '(') depth++;
    else if (c == '}' || c == ']' || c == ')') depth--;
    if (c == ',' && depth == 0) { out.push_back(trim(cur)); cur.clear(); continue; }
    cur += c;
  }
  if (!cur.empty() || !out.empty()) out.push_back(trim(cur));
  return out;
}

// [ "a", "b" ] → a, b
static std::vector<std::string> parseStringList(const std::string &a) {
  std::vector<std::string> out;
  auto s = trim(a);
  if (s.size() < 2 || s.front() != '[' || s.back() != ']') return out;
  for (auto &item : splitArgs(s.substr(1, s.size() - 2)))
    if (!item.empty()) out.push_back(unquoteArg(item));
  return out;
}

// { AF_INET 1.2.3.4:443 } / { AF_INET6 [::1]:443 } / { AF_UNIX "/p" }
static bool parseSockaddr(const std::string &a, Event &ev) {
  auto s = trim(a);
  if (s.size() < 2 || s.front() != '{' || s.back() != '}') return false;
  s = trim(s.substr(1, s.size() - 2));
  auto sp = s.find(' ');
  std::string fam  = sp == std::string::npos ? s : s.substr(0, sp);
  std::string rest = sp == std::string::npos ? "" : trim(s.substr(sp + 1));
  if (fam == "AF_INET") {
    ev.family = "inet";
    auto c = rest.rfind(':');
    if (c == std::string::npos) return false;
    ev.host = rest.substr(0, c);
    ev.port = toUnsigned(rest.substr(c + 1));
    return true;
  }
  if (fam == "AF_INET6") {
    ev.family = "inet6";
    if (rest.empty() || rest[0] != '[') return false;
    auto e = rest.find(']');
    if (e == std::string::npos) return false;
    ev.host = rest.substr(1, e - 1);
    if (e + 1 < rest.size() && rest[e + 1] == ':') ev.port = toUnsigned(rest.substr(e + 2));
    return true;
  }
  if (fam == "AF_UNIX" || fam == "AF_LOCAL") {
    ev.family = "unix";
    ev.path = unquoteArg(rest);
    return true;
  }
  return false;
}

static bool openFlagsWrite(const std::string &f) {
  return f.find("O_WRONLY") != std::string::npos || f.find("O_RDWR") != std::string::npos
         || f.find("O_CREAT") != std::string::npos || f.find("O_TRUNC") != std::string::npos
         || f.find("O_APPEND") != std::string::npos;
}

// ---------------------------------------------------------------- parseLine

bool parseLine(const std::string &line, Event &out) {
  out = Event();
  size_t i = 0;
  auto skipSp = [&]() { while (i < line.size() && line[i] == ' ') i++; };
  auto digitsEnd = [&](size_t from) { while (from < line.size() && std::isdigit((unsigned char)line[from])) from++; return from; };
  skipSp();

  // optional "<sec>.<nsec> " (truss -d / -D)
  {
    size_t j = digitsEnd(i);
    if (j > i && j < line.size() && line[j] == '.') {
      size_t k = digitsEnd(j + 1);
      if (k > j + 1 && k < line.size() && line[k] == ' ') { i = k; skipSp(); }
    }
  }
  // optional "<pid>: " or "<pid> <tid>: " (truss -f / -H)
  {
    size_t j = digitsEnd(i);
    if (j > i) {
      if (j < line.size() && line[j] == ':') {
        out.pid = std::strtol(line.substr(i, j - i).c_str(), nullptr, 10);
        i = j + 1; skipSp();
      } else {
        size_t k = j;
        while (k < line.size() && line[k] == ' ') k++;
        size_t m = digitsEnd(k);
        if (m > k && m < line.size() && line[m] == ':') {
          out.pid = std::strtol(line.substr(i, j - i).c_str(), nullptr, 10);
          i = m + 1; skipSp();
        }
      }
    }
  }

  size_t p = line.find('(', i);
  if (p == std::string::npos) return false;
  const std::string name = line.substr(i, p - i);
  if (name.empty() || !std::isalpha((unsigned char)name[0])) return false;
  for (char c : name)
    if (!std::isalnum((unsigned char)c) && c != '_') return false;

  // the matching ')' — quoted strings may contain parentheses
  size_t q = p + 1;
  int depth = 1;
  while (q < line.size() && depth > 0) {
    char c = line[q];
    if (c == '"') {
      std::string tmp;
      size_t pp = q;
      if (!unquote(line, pp, tmp)) return false;
      q = pp;
      continue;
    }
    if (c == '(') depth++;
    else if (c == ')') depth--;
    if (depth > 0) q++;
  }
  if (depth != 0) return false;
  const std::string argsStr = line.substr(p + 1, q - p - 1);
  const std::string rest = line.substr(q + 1);
  out.failed = rest.find("ERR#") != std::string::npos;
  long result = -1;
  if (auto eq = rest.find('='); eq != std::string::npos)
    result = std::strtol(rest.c_str() + eq + 1, nullptr, 10);

  const auto args = splitArgs(argsStr);
  using K = Event::Kind;
  if (name == "open") {
    if (args.size() < 2) return false;
    out.kind = K::Open; out.path = unquoteArg(args[0]); out.write = openFlagsWrite(args[1]);
  } else if (name == "openat") {
    if (args.size() < 3) return false;
    out.kind = K::Open; out.path = unquoteArg(args[1]); out.write = openFlagsWrite(args[2]);
  } else if (name == "stat" || name == "lstat" || name == "access" || name == "eaccess" || name == "readlink") {
    if (args.empty()) return false;
    out.kind = K::Stat; out.path = unquoteArg(args[0]);
  } else if (name == "fstatat" || name == "faccessat" || name == "readlinkat") {
    if (args.size() < 2) return false;
    out.kind = K::Stat; out.path = unquoteArg(args[1]);
  } else if (name == "execve") {
    if (args.empty()) return false;
    out.kind = K::Exec; out.path = unquoteArg(args[0]);
    if (args.size() > 1) out.argv = parseStringList(args[1]);
  } else if (name == "socket") {
    if (args.size() < 2) return false;
    out.kind = K::Socket;
    if (args[0].find("INET6") != std::string::npos)      out.family = "inet6";
    else if (args[0].find("INET") != std::string::npos)  out.family = "inet";
    else if (args[0].find("UNIX") != std::string::npos || args[0].find("LOCAL") != std::string::npos) out.family = "unix";
    else                                                 out.family = "other";
    out.datagram = args[1].find("SOCK_DGRAM") != std::string::npos;
    out.fd = (int)result;
  } else if (name == "connect" || name == "bind") {
    if (args.size() < 2) return false;
    out.kind = name == "connect" ? K::Connect : K::Bind;
    out.fd = (int)std::strtol(args[0].c_str(), nullptr, 10);
    if (!parseSockaddr(args[1], out)) return false;
    if (out.kind == K::Connect && out.failed && rest.find("in progress") != std::string::npos)
      out.failed = false;   // non-blocking connect: the destination is real
  } else if (name == "listen") {
    if (args.empty()) return false;
    out.kind = K::Listen; out.fd = (int)std::strtol(args[0].c_str(), nullptr, 10);
  } else if (name == "sendto") {
    if (args.size() < 5) return false;
    out.kind = K::Sendto; out.fd = (int)std::strtol(args[0].c_str(), nullptr, 10);
    if (!parseSockaddr(args[4], out)) return false;
  } else {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------- summarize

Summary summarize(const std::vector<std::string> &lines) {
  Summary s;
  struct SockInfo { std::string family; bool datagram; };
  std::map<std::pair<long, int>, SockInfo> socks;
  std::map<std::pair<long, int>, Endpoint> bound;
  std::set<std::string> seenExec;

  for (auto &line : lines) {
    s.lines++;
    Event ev;
    if (!parseLine(line, ev)) continue;
    s.parsed++;
    const auto key = std::make_pair(ev.pid, ev.fd);
    const bool absolute = !ev.path.empty() && ev.path[0] == '/';
    using K = Event::Kind;
    switch (ev.kind) {
    case K::Open:
      if (!ev.failed && absolute) (ev.write ? s.writePaths : s.readPaths).insert(ev.path);
      break;
    case K::Stat:
      if (!ev.failed && absolute) s.probedPaths.insert(ev.path);
      break;
    case K::Exec:
      if (!ev.failed && absolute && seenExec.insert(ev.path).second) {
        s.execs.push_back(ev.path);
        s.execArgv.push_back(ev.argv);
      }
      break;
    case K::Socket:
      if (!ev.failed && ev.fd >= 0) socks[key] = {ev.family, ev.datagram};
      break;
    case K::Connect:
      if (ev.failed) break;
      if (ev.family == "unix") {
        if (!ev.path.empty()) s.unixSockets.insert(ev.path);
      } else {
        auto it = socks.find(key);
        Endpoint e;
        e.host = ev.host; e.port = ev.port;
        e.udp = it != socks.end() && it->second.datagram;
        s.outbound.insert(e);
      }
      break;
    case K::Sendto:
      if (!ev.failed && ev.family != "unix") {
        Endpoint e;
        e.host = ev.host; e.port = ev.port; e.udp = true;
        s.outbound.insert(e);
      }
      break;
    case K::Bind:
      if (ev.failed || ev.family == "unix") break;
      {
        auto it = socks.find(key);
        Endpoint e;
        e.host = ev.host; e.port = ev.port;
        e.udp = it != socks.end() && it->second.datagram;
        if (e.udp) { if (e.port) s.listening.insert(e); }
        else bound[key] = e;
      }
      break;
    case K::Listen:
      if (!ev.failed) {
        auto it = bound.find(key);
        if (it != bound.end() && it->second.port) s.listening.insert(it->second);
      }
      break;
    case K::None:
      break;
    }
  }
  return s;
}

// ---------------------------------------------------------------- helpers

std::string pkgNameFromNameVersion(const std::string &nv) {
  // the version starts after the last '-' that is followed by a digit
  for (size_t i = nv.size(); i-- > 1;)
    if (nv[i - 1] == '-' && std::isdigit((unsigned char)nv[i]))
      return nv.substr(0, i - 1);
  return nv;
}

std::map<std::string, std::string> parsePkgWhichOutput(const std::string &out) {
  std::map<std::string, std::string> m;
  static const std::string kMarker = " was installed by package ";
  std::istringstream is(out);
  std::string line;
  while (std::getline(is, line)) {
    auto k = line.find(kMarker);
    if (k == std::string::npos || k == 0) continue;
    auto path = line.substr(0, k);
    auto nv = trim(line.substr(k + kMarker.size()));
    if (!nv.empty()) m[path] = pkgNameFromNameVersion(nv);
  }
  return m;
}

static bool isPrivateV4(const std::string &h) {
  if (startsWith(h, "10.") || startsWith(h, "192.168.") || startsWith(h, "169.254.")) return true;
  if (startsWith(h, "172.")) {
    auto second = toUnsigned(h.substr(4));
    return second >= 16 && second <= 31;
  }
  return false;
}

std::string classifyHost(const std::string &hostIn, unsigned port) {
  std::string h = hostIn;
  if (startsWith(h, "::ffff:")) h = h.substr(7);   // IPv4-mapped
  if (port == 53) return "dns";
  if (startsWith(h, "127.") || h == "::1" || h == "0.0.0.0" || h == "::") return "host";
  std::string lower;
  for (char c : h) lower += (char)std::tolower((unsigned char)c);
  if (isPrivateV4(h) || startsWith(lower, "fe80:") || startsWith(lower, "fc") || startsWith(lower, "fd"))
    return "lan";
  return "wan";
}

std::string homeRelative(const std::string &path, const std::string &home) {
  if (home.empty() || home == "/" || path.empty()) return "";
  std::string h = home;
  while (h.size() > 1 && h.back() == '/') h.pop_back();
  if (isUnder(path, h)) return "$HOME" + path.substr(h.size());
  if (startsWith(h, "/home/")) {                       // FreeBSD: /home -> /usr/home
    const std::string alt = "/usr" + h;
    if (isUnder(path, alt)) return "$HOME" + path.substr(alt.size());
  }
  return "";
}

std::string yamlScalar(const std::string &s) {
  bool bare = !s.empty();
  for (char c : s)
    if (!(std::isalnum((unsigned char)c) || c == '_' || c == '.' || c == '/' || c == '$' || c == '+' || c == '~' || c == '-'))
      { bare = false; break; }
  if (bare && (s[0] == '-' || s == "~" || s == "true" || s == "false" || s == "null"))
    bare = false;
  if (bare) return s;
  std::string out = "\"";
  for (char c : s) {
    if (c == '\\' || c == '"') { out += '\\'; out += c; }
    else if (c == '\n') out += "\\n";
    else if (c == '\t') out += "\\t";
    else out += c;
  }
  return out + "\"";
}

// ---------------------------------------------------------------- generate

static const std::vector<std::string> &ignoredPrefixes() {
  static const std::vector<std::string> v = {
    "/dev", "/proc", "/tmp", "/var/tmp", "/var/run", "/var/db", "/var/cache", "/var/log",
    "/var/mail", "/var/spool", "/var/empty", "/etc", "/lib", "/libexec", "/bin", "/sbin", "/rescue",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib32", "/usr/libexec", "/usr/libdata",
    "/usr/share", "/usr/include", "/usr/local", "/compat", "/boot", "/usr/src", "/usr/obj",
    "/usr/ports", "/net", "/media", "/mnt",
  };
  return v;
}

static bool isIgnored(const std::string &p) {
  for (auto &pre : ignoredPrefixes())
    if (isUnder(p, pre)) return true;
  return false;
}

static void pushUnique(std::vector<std::string> &v, const std::string &s) {
  if (std::find(v.begin(), v.end(), s) == v.end()) v.push_back(s);
}

static std::vector<std::string> splitPath(const std::string &rel) {
  std::vector<std::string> comps;
  std::string cur;
  for (char c : rel) {
    if (c == '/') { if (!cur.empty()) comps.push_back(cur); cur.clear(); }
    else cur += c;
  }
  if (!cur.empty()) comps.push_back(cur);
  return comps;
}

Generated generate(const Summary &s, const Input &in) {
  Generated g;

  // --- run/command
  if (!in.command.empty()) {
    g.command = in.command;
  } else if (!s.execs.empty()) {
    g.command.push_back(s.execs[0]);
    const auto &av = s.execArgv[0];
    for (size_t i = 1; i < av.size(); i++) g.command.push_back(av[i]);
  }

  // --- packages: executed files decide pkg/install, the rest is a note
  std::set<std::string> execPkgs, readPkgs, unownedLocal;
  auto ownerOf = [&](const std::string &p) -> std::string {
    auto it = in.pkgOwner.find(p);
    return it == in.pkgOwner.end() ? "" : it->second;
  };
  for (auto &e : s.execs)
    if (isUnder(e, "/usr/local")) {
      auto o = ownerOf(e);
      if (!o.empty()) execPkgs.insert(o); else unownedLocal.insert(e);
    }
  auto allOpened = s.readPaths;
  allOpened.insert(s.writePaths.begin(), s.writePaths.end());
  for (auto &p : allOpened)
    if (isUnder(p, "/usr/local")) {
      auto o = ownerOf(p);
      if (!o.empty()) { if (!execPkgs.count(o)) readPkgs.insert(o); }
      else if (!isUnder(p, "/usr/local/etc") && !isUnder(p, "/usr/local/share/certs")) unownedLocal.insert(p);
    }
  g.pkgs.assign(execPkgs.begin(), execPkgs.end());
  g.otherPkgs.assign(readPkgs.begin(), readPkgs.end());

  // --- devices, certificates, home, elsewhere
  bool sound = false, input = false, usb = false, cache = false;
  std::set<std::string> otherDirs;
  static const std::set<std::string> loginDotfiles = {
    ".Xauthority", ".ICEauthority", ".Xdefaults", ".Xresources", ".xsession-errors", ".sh_history",
    ".history", ".login_conf", ".profile", ".cshrc", ".shrc", ".login", ".logout", ".mailrc",
    ".mail_aliases", ".rhosts", ".hushlogin", ".bash_history", ".zsh_history",
  };
  for (auto &p : allOpened) {
    if (isUnder(p, "/dev")) {
      if (isUnder(p, "/dev/dri")) g.gl = true;
      else if (startsWith(p, "/dev/video")) g.video = true;
      else if (startsWith(p, "/dev/dsp") || startsWith(p, "/dev/mixer") || p == "/dev/sndstat") sound = true;
      else if (isUnder(p, "/dev/input")) input = true;
      else if (startsWith(p, "/dev/ugen") || startsWith(p, "/dev/usb") || startsWith(p, "/dev/u2f")) usb = true;
      continue;
    }
    if (isUnder(p, "/etc/ssl") || isUnder(p, "/usr/local/share/certs") || isUnder(p, "/usr/local/etc/ssl")) {
      g.sslCerts = true;
      continue;
    }
    const auto rel = homeRelative(p, in.home);
    if (!rel.empty()) {
      auto comps = splitPath(rel.substr(5));   // after "$HOME"
      if (comps.empty()) continue;
      const auto &top = comps[0];
      if (loginDotfiles.count(top)) continue;
      if (top == ".cache") { cache = true; continue; }
      if (comps.size() == 1) { pushUnique(g.fileShares, "$HOME/" + top); continue; }
      std::string dir = "$HOME/" + top;
      if (top == ".config" || top == ".local") {
        // one application's slice, not the whole tree
        if (top == ".config") dir += "/" + comps[1];
        else if (comps.size() >= 3 && (comps[1] == "share" || comps[1] == "state")) dir += "/" + comps[1] + "/" + comps[2];
        else dir += "/" + comps[1];
      }
      if (top[0] == '.') pushUnique(g.stateDirShares, dir);
      else pushUnique(g.dirShares, dir);
      continue;
    }
    if (isIgnored(p)) continue;
    otherDirs.insert(dirname(p));
  }
  // directories elsewhere: keep the shortest ancestors only
  for (auto &d : otherDirs) {
    bool covered = false;
    for (auto &o : otherDirs)
      if (o != d && isUnder(d, o)) { covered = true; break; }
    if (!covered && d != "/") pushUnique(g.dirShares, d);
  }

  // --- unix sockets
  for (auto &u : s.unixSockets) {
    if (u.find("/.X11-unix/") != std::string::npos) g.x11 = true;
    else if (u.size() >= 18 && u.compare(u.size() - 18, 18, "/system_bus_socket") == 0) g.dbusSystem = true;
    else if ((u.size() >= 4 && u.compare(u.size() - 4, 4, "/bus") == 0) || u.find("session_bus_socket") != std::string::npos) g.dbusSession = true;
    else if (u.find("/pulse/native") != std::string::npos || u.find("/pipewire-0") != std::string::npos) sound = true;
    else if (u.find("wayland-") != std::string::npos)
      pushUnique(g.notes, "Wayland display socket " + u + ": run under `gui: {mode: wayland}` (the X11 option covers only X)");
    else
      pushUnique(g.notes, "unix socket " + u + " was used; share it with socket_proxy/share or dirs/share if the program needs it");
  }

  // --- network
  std::set<std::string> classes;
  for (auto &e : s.outbound) {
    if (e.port == 0) continue;
    classes.insert(classifyHost(e.host, e.port));
    std::string host = e.host.find(':') != std::string::npos ? "[" + e.host + "]" : e.host;
    pushUnique(g.outboundSeen, host + ":" + std::to_string(e.port) + (e.udp ? "/udp" : "/tcp"));
  }
  for (const char *c : {"wan", "lan", "host", "dns"})
    if (classes.count(c)) g.outbound.push_back(c);
  for (auto &l : s.listening) {
    auto &v = l.udp ? g.inboundUdp : g.inboundTcp;
    if (std::find(v.begin(), v.end(), l.port) == v.end()) v.push_back(l.port);
  }
  std::sort(g.inboundTcp.begin(), g.inboundTcp.end());
  std::sort(g.inboundUdp.begin(), g.inboundUdp.end());
  g.net = !g.outbound.empty() || !g.inboundTcp.empty() || !g.inboundUdp.empty();

  // --- notes
  if (sound) pushUnique(g.notes, "sound was used (OSS device or PulseAudio/PipeWire socket): no spec option generates this — PipeWire/PulseAudio sockets are bound by `gui: {mode: wayland}`, OSS devices need terminal/devfs_ruleset");
  if (input) pushUnique(g.notes, "/dev/input was read: raw input devices are not exposed by default (terminal/devfs_ruleset)");
  if (usb)   pushUnique(g.notes, "USB devices (/dev/ugen, /dev/usb, /dev/u2f) were opened: expose them with terminal/devfs_ruleset");
  if (cache) pushUnique(g.notes, "$HOME/.cache was used: left per container (nothing to share); a tmpfs there is the usual choice");
  if (!unownedLocal.empty()) {
    std::string list;
    size_t n = 0;
    for (auto &p : unownedLocal) { if (n++ == 8) { list += " ..."; break; } list += (list.empty() ? "" : " ") + p; }
    pushUnique(g.notes, "files under /usr/local not owned by any package (ports built locally? pkg not queried?): " + list);
  }
  if (s.execs.empty() && in.command.empty())
    pushUnique(g.notes, "no execve seen in the trace: set run/command by hand");
  return g;
}

// ---------------------------------------------------------------- render

static void renderShareList(std::ostringstream &o, const std::vector<std::string> &items) {
  for (auto &d : items) o << "        - [" << yamlScalar(d) << ", " << yamlScalar(d) << "]\n";
}

std::string renderSpec(const Generated &g, const std::string &crateVersion) {
  std::ostringstream o;
  o << "##\n";
  o << "## generated by crate profile-from-trace (crate " << crateVersion << ")\n";
  if (!g.command.empty()) {
    o << "## from one run of:";
    for (auto &w : g.command) o << " " << w;
    o << "\n";
  }
  o << "## Review before use: the shares and packages below are what the program\n";
  o << "## TOUCHED during that run, not what it needs. Drop what is not wanted.\n";
  o << "##\n\n---\n";

  if (!g.pkgs.empty()) {
    o << "\npkg:\n    install:\n";
    for (auto &p : g.pkgs) o << "        - " << yamlScalar(p) << "\n";
  }
  if (!g.otherPkgs.empty()) {
    o << "    # also read from these packages (dependencies, usually pulled in automatically):\n";
    o << "    #  ";
    for (auto &p : g.otherPkgs) o << " " << p;
    o << "\n";
  }

  if (!g.command.empty()) {
    o << "\nrun:\n    command:";
    std::string cmd;
    for (auto &w : g.command) cmd += (cmd.empty() ? "" : " ") + w;
    o << " " << yamlScalar(cmd) << "\n";
  }

  if (!g.dirShares.empty() || !g.stateDirShares.empty()) {
    o << "\ndirs:\n    share:\n";
    renderShareList(o, g.dirShares);
    if (!g.stateDirShares.empty()) {
      o << "        # application state (profile, config, data); remove to keep it per container\n";
      renderShareList(o, g.stateDirShares);
    }
  }
  if (!g.fileShares.empty()) {
    o << "\nfiles:\n    share:\n";
    renderShareList(o, g.fileShares);
  }

  // options: the list form when nothing carries details, the map form otherwise
  const bool netDetails = g.net && !(g.outbound.size() == 4 && g.inboundTcp.empty() && g.inboundUdp.empty());
  std::vector<std::string> plain;
  if (g.net && !netDetails) plain.push_back("net");
  if (g.x11)      plain.push_back("x11");
  if (g.gl)       plain.push_back("gl");
  if (g.video)    plain.push_back("video");
  if (g.sslCerts) plain.push_back("ssl-certs");
  if (netDetails || !plain.empty()) {
    o << "\noptions:\n";
    if (netDetails) {
      o << "    net:\n";
      if (!g.outbound.empty()) {
        o << "        outbound: [";
        for (size_t i = 0; i < g.outbound.size(); i++) o << (i ? ", " : "") << g.outbound[i];
        o << "]\n";
      } else {
        o << "        outbound: none\n";
      }
      if (!g.inboundTcp.empty()) {
        o << "        inbound-tcp:\n";
        for (auto p : g.inboundTcp) o << "            " << p << ": " << p << "\n";
      }
      if (!g.inboundUdp.empty()) {
        o << "        inbound-udp:\n";
        for (auto p : g.inboundUdp) o << "            " << p << ": " << p << "\n";
      }
      for (auto &p : plain) o << "    " << p << ":\n";
    } else {
      for (auto &p : plain) o << "    - " << p << "\n";
    }
  }

  if (g.dbusSystem || g.dbusSession) {
    o << "\ndbus:\n";
    if (g.dbusSystem)  o << "    system: true\n";
    if (g.dbusSession) o << "    session: true\n";
    o << "    # add policy/allow_own and policy/deny_send for the services this program talks to\n";
  }

  if (!g.outboundSeen.empty()) {
    o << "\n# outbound destinations seen:";
    for (auto &d : g.outboundSeen) o << " " << d;
    o << "\n";
  }
  if (!g.notes.empty()) {
    o << "\n# notes:\n";
    for (auto &n : g.notes) o << "#   - " << n << "\n";
  }
  return o.str();
}

} // namespace TracePure
