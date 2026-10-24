// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "jail_audit_pure.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace JailAuditPure {

namespace {

using DoctorPure::Check;
using DoctorPure::Report;
using DoctorPure::failCheck;
using DoctorPure::passCheck;
using DoctorPure::warnCheck;

std::string trim(const std::string &s) {
  size_t b = 0, e = s.size();
  while (b < e && std::isspace((unsigned char)s[b])) b++;
  while (e > b && std::isspace((unsigned char)s[e - 1])) e--;
  return s.substr(b, e - b);
}

std::vector<std::string> lines(const std::string &text) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : text) {
    if (c == '\n') { out.push_back(cur); cur.clear(); }
    else if (c != '\r') cur += c;
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}

std::vector<std::string> words(const std::string &line) {
  std::vector<std::string> out;
  std::istringstream is(line);
  std::string w;
  while (is >> w) out.push_back(w);
  return out;
}

std::vector<std::string> splitOn(const std::string &s, char sep) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == sep) { out.push_back(cur); cur.clear(); }
    else cur += c;
  }
  out.push_back(cur);
  return out;
}

bool startsWith(const std::string &s, const std::string &p) {
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

std::string lower(std::string s) {
  for (auto &c : s) c = (char)std::tolower((unsigned char)c);
  return s;
}

std::string join(const std::vector<std::string> &v, const std::string &sep, size_t max = 0) {
  std::string out;
  size_t n = (max && v.size() > max) ? max : v.size();
  for (size_t i = 0; i < n; i++) {
    if (i) out += sep;
    out += v[i];
  }
  if (n < v.size()) out += sep + "… (" + std::to_string(v.size() - n) + " more)";
  return out;
}

int toInt(const std::string &s, int dflt = 0) {
  if (s.empty()) return dflt;
  for (char c : s) if (!std::isdigit((unsigned char)c) && c != '-') return dflt;
  try { return std::stoi(s); } catch (...) { return dflt; }
}

// Path `p` is `dir` itself or inside it ("/" contains everything).
bool under(const std::string &p, const std::string &dir) {
  if (dir == "/") return !p.empty() && p[0] == '/';
  return p == dir || startsWith(p, dir + "/");
}

} // anon

// ---------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------

std::string probeScript(bool offline, const std::string &dnsName) {
  std::string s;
  s += "PATH=/sbin:/bin:/usr/sbin:/usr/bin; export PATH\n";
  s += "echo @@id; id 2>&1\n";
  s += "echo @@sysctl; sysctl -e kern.securelevel kern.hostname kern.hostid kern.hostuuid kern.osrelease security.jail 2>/dev/null\n";
  s += "echo @@mount; mount -p 2>&1\n";
  s += "echo @@ifconfig; ifconfig -a 2>&1\n";
  s += "echo @@routes; netstat -rn -f inet 2>/dev/null; netstat -rn -f inet6 2>/dev/null\n";
  s += "echo @@dev; ls -1 /dev 2>&1\n";
  s += "echo @@sockets; sockstat -l 2>&1\n";
  s += "echo @@fssockets; find /tmp /var/run /var/tmp -maxdepth 3 -type s 2>/dev/null\n";
  s += "echo @@ps; ps -axo user=,pid=,ucomm= 2>&1\n";
  s += "echo @@resolv; cat /etc/resolv.conf 2>/dev/null\n";
  s += "gw=$(netstat -rn -f inet 2>/dev/null | awk '$1==\"default\"{print $2; exit}')\n";
  s += "echo \"@@gw $gw\"\n";
  if (!offline) {
    // One TCP connect to the default gateway (the host side of the
    // epair, or the LAN router). Port 22: "refused" and "open" both
    // prove reachability, "timed out" / "no route" the opposite. The
    // gateway must look like a dotted quad before it is put on a
    // command line.
    s += "case \"$gw\" in\n";
    s += "  ''|*[!0-9.]*) echo @@connect; echo @@rc=255 ;;\n";
    s += "  *) echo @@connect; nc -z -w 3 \"$gw\" 22 2>&1; echo \"@@rc=$?\" ;;\n";
    s += "esac\n";
    // One DNS lookup through the jail's own resolver.
    s += "echo @@dns; drill -Q A '" + dnsName + "' 2>&1; echo \"@@rc=$?\"\n";
  }
  return s;
}

std::map<std::string, std::string> splitSections(const std::string &out) {
  std::map<std::string, std::string> sections;
  std::string cur;
  for (const auto &raw : lines(out)) {
    if (startsWith(raw, "@@")) {
      std::string marker = trim(raw.substr(2));
      if (startsWith(marker, "rc=")) {
        if (!cur.empty()) sections[cur + ".rc"] = trim(marker.substr(3));
        continue;
      }
      auto sp = marker.find(' ');
      std::string name = sp == std::string::npos ? marker : marker.substr(0, sp);
      std::string arg  = sp == std::string::npos ? "" : trim(marker.substr(sp + 1));
      if (name.empty()) continue;
      cur = name;
      sections[cur] = arg.empty() ? "" : arg + "\n";
      continue;
    }
    if (!cur.empty()) sections[cur] += raw + "\n";
  }
  return sections;
}

// ---------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------

std::vector<Mount> parseMountP(const std::string &text) {
  std::vector<Mount> out;
  for (const auto &l : lines(text)) {
    auto w = words(l);
    if (w.size() < 4) continue;
    Mount m;
    m.special = w[0];
    m.node    = w[1];
    m.fstype  = w[2];
    m.opts    = w[3];
    for (const auto &o : splitOn(m.opts, ','))
      if (o == "ro") m.readOnly = true;
    out.push_back(m);
  }
  return out;
}

std::vector<Iface> parseIfconfig(const std::string &text) {
  std::vector<Iface> out;
  for (const auto &l : lines(text)) {
    if (l.empty()) continue;
    if (!std::isspace((unsigned char)l[0])) {
      auto colon = l.find(": flags=");
      if (colon == std::string::npos) continue;
      Iface i;
      i.name = l.substr(0, colon);
      auto lt = l.find('<', colon), gt = l.find('>', colon);
      if (lt != std::string::npos && gt != std::string::npos && gt > lt)
        for (const auto &f : splitOn(l.substr(lt + 1, gt - lt - 1), ','))
          if (f == "UP") i.up = true;
      out.push_back(i);
      continue;
    }
    if (out.empty()) continue;
    auto w = words(l);
    if (w.size() < 2) continue;
    if (w[0] == "inet") {
      out.back().inet.push_back(w[1]);
    } else if (w[0] == "inet6") {
      std::string a = w[1];
      auto pct = a.find('%');
      if (pct != std::string::npos) a = a.substr(0, pct);
      out.back().inet6.push_back(a);
    }
  }
  return out;
}

Routes parseDefaultRoutes(const std::string &text) {
  Routes r;
  for (const auto &l : lines(text)) {
    auto w = words(l);
    if (w.size() < 2 || w[0] != "default") continue;
    if (w[1].find(':') != std::string::npos) { if (r.gw6.empty()) r.gw6 = w[1]; }
    else                                     { if (r.gw4.empty()) r.gw4 = w[1]; }
  }
  return r;
}

std::vector<std::string> parseLines(const std::string &text) {
  std::vector<std::string> out;
  for (const auto &l : lines(text)) {
    auto t = trim(l);
    if (!t.empty()) out.push_back(t);
  }
  return out;
}

std::vector<Socket> parseSockstat(const std::string &text) {
  std::vector<Socket> out;
  for (const auto &l : lines(text)) {
    auto w = words(l);
    if (w.size() < 6 || w[0] == "USER") continue;
    Socket s;
    s.user    = w[0];
    s.command = w[1];
    s.pid     = toInt(w[2]);
    s.proto   = w[4];
    s.local   = w[5];
    if (w.size() >= 7) s.foreign = w[6];
    out.push_back(s);
  }
  return out;
}

std::map<std::string, std::string> parseSysctl(const std::string &text) {
  std::map<std::string, std::string> out;
  for (const auto &l : lines(text)) {
    auto eq = l.find('='), colon = l.find(": ");
    size_t pos; size_t skip;
    if (eq == std::string::npos && colon == std::string::npos) continue;
    if (colon == std::string::npos || (eq != std::string::npos && eq < colon)) { pos = eq; skip = 1; }
    else { pos = colon; skip = 2; }
    std::string key = trim(l.substr(0, pos));
    if (key.empty() || startsWith(key, "security.jail.param")) continue;
    out[key] = trim(l.substr(pos + skip));
  }
  return out;
}

std::vector<Proc> parsePs(const std::string &text) {
  std::vector<Proc> out;
  for (const auto &l : lines(text)) {
    auto w = words(l);
    if (w.size() < 3) continue;
    Proc p;
    p.user = w[0];
    p.pid  = toInt(w[1], -1);
    if (p.pid < 0) continue;
    for (size_t i = 2; i < w.size(); i++) p.command += (i > 2 ? " " : "") + w[i];
    out.push_back(p);
  }
  return out;
}

std::vector<std::string> parseResolvConf(const std::string &text) {
  std::vector<std::string> out;
  for (const auto &l : lines(text)) {
    auto w = words(l);
    if (w.size() >= 2 && w[0] == "nameserver") out.push_back(w[1]);
  }
  return out;
}

// ---------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------

Reach classifyNc(int rc, const std::string &text) {
  auto t = lower(text);
  if (rc == 0 || t.find("succeeded") != std::string::npos) return Reach::Open;
  if (t.find("refused") != std::string::npos) return Reach::Refused;
  if (t.find("timed out") != std::string::npos || t.find("no route") != std::string::npos ||
      t.find("unreachable") != std::string::npos || t.find("permission denied") != std::string::npos)
    return Reach::Unreachable;
  return Reach::Unknown;
}

const char *reachLabel(Reach r) {
  switch (r) {
  case Reach::Open:        return "open";
  case Reach::Refused:     return "refused";
  case Reach::Unreachable: return "unreachable";
  case Reach::Unknown:     return "unknown";
  }
  return "unknown";
}

DeviceClasses classifyDevices(const std::vector<std::string> &names) {
  DeviceClasses d;
  auto any = [](const std::string &n, std::initializer_list<const char*> prefixes) {
    for (const char *p : prefixes) if (startsWith(n, p)) return true;
    return false;
  };
  auto is = [](const std::string &n, std::initializer_list<const char*> exact) {
    for (const char *e : exact) if (n == e) return true;
    return false;
  };
  for (const auto &n : names) {
    if (n == "dri" || any(n, {"drm", "nvidia"}))                               d.gpu.push_back(n);
    else if (any(n, {"video"}))                                                 d.video.push_back(n);
    else if (is(n, {"sndstat"}) || any(n, {"dsp", "mixer", "audio", "midi"}))   d.sound.push_back(n);
    else if (is(n, {"input", "sysmouse"}) ||
             any(n, {"kbd", "ukbd", "atkbd", "kbdmux", "ums", "uhid", "joy", "psm", "ttyv"}))
                                                                                d.input.push_back(n);
    else if (is(n, {"usb", "usbctl"}) || any(n, {"ugen"}))                      d.usb.push_back(n);
    else if (any(n, {"cua", "ttyu", "ttyU"}))                                   d.serial.push_back(n);
    else if (is(n, {"gpt", "diskid", "ufs", "ufsid", "label", "zvol", "mdctl"}) ||
             any(n, {"ada", "da", "nvd", "nda", "md", "cd", "geom"}))           d.disks.push_back(n);
    else if (is(n, {"mem", "kmem", "io", "pf", "kvm"}) || any(n, {"bpf"}))      d.raw.push_back(n);
    else if (is(n, {"net", "netmap"}) || any(n, {"tun", "tap"}))                d.net.push_back(n);
    else d.other++;
  }
  return d;
}

const Mount *hostMountFor(const std::string &path, const std::vector<Mount> &mounts) {
  const Mount *best = nullptr;
  for (const auto &m : mounts) {
    if (m.fstype != "nullfs") continue;
    if (!under(path, m.node)) continue;
    if (!best || m.node.size() > best->node.size()) best = &m;
  }
  return best;
}

bool isWideHostPath(const std::string &hostPathIn) {
  std::string p = hostPathIn;
  while (p.size() > 1 && p.back() == '/') p.pop_back();
  static const char *wide[] = {"/", "/home", "/usr/home", "/root", "/etc", "/usr", "/var",
                               "/usr/local", "/usr/local/etc", "/var/run", "/var/db", "/boot"};
  for (const char *w : wide) if (p == w) return true;
  // a user's home root: /home/<u> or /usr/home/<u>
  for (const char *base : {"/home/", "/usr/home/"}) {
    if (startsWith(p, base)) {
      std::string rest = p.substr(std::string(base).size());
      if (!rest.empty() && rest.find('/') == std::string::npos) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------

namespace {

std::string firstLine(const std::string &text) {
  auto ls = parseLines(text);
  return ls.empty() ? "" : ls[0];
}

void jailChecks(Report &r, const std::map<std::string, std::string> &m, const HostContext &ctx) {
  auto get = [&](const char *k) -> const std::string* {
    auto it = m.find(k);
    return it == m.end() ? nullptr : &it->second;
  };
  if (auto v = get("security.jail.jailed")) {
    if (*v == "1") r.checks.push_back(passCheck("jail", "jailed", "security.jail.jailed=1"));
    else r.checks.push_back(failCheck("jail", "jailed", "security.jail.jailed=" + *v + " — the probe did not run inside a jail"));
  } else {
    r.checks.push_back(warnCheck("jail", "jailed", "security.jail.jailed not reported by sysctl(8) in the jail"));
  }
  if (auto v = get("kern.hostname")) {
    if (!ctx.hostHostname.empty() && *v == ctx.hostHostname)
      r.checks.push_back(warnCheck("jail", "hostname", *v + " — same as the host's"));
    else
      r.checks.push_back(passCheck("jail", "hostname", *v));
  }
  if (auto v = get("kern.hostid")) {
    if (!ctx.hostHostid.empty() && *v == ctx.hostHostid && *v != "0")
      r.checks.push_back(warnCheck("jail", "hostid", "kern.hostid " + *v + " — same as the host (identifies the machine to anything that reads it)"));
    else
      r.checks.push_back(passCheck("jail", "hostid", "kern.hostid " + *v + (ctx.hostHostid.empty() ? "" : " (differs from the host)")));
  }
  if (auto v = get("kern.securelevel"))
    r.checks.push_back(passCheck("jail", "securelevel", "kern.securelevel " + *v));
  if (auto v = get("kern.osrelease"))
    r.checks.push_back(passCheck("jail", "osrelease", *v));
  if (auto v = get("security.jail.vnet"))
    r.checks.push_back(passCheck("jail", "vnet", *v == "1" ? "own network stack (vnet)" : "shared network stack (no vnet)"));
  if (auto v = get("security.jail.allow_raw_sockets")) {
    if (*v == "1") r.checks.push_back(warnCheck("jail", "raw-sockets", "allowed (allow.raw_sockets) — ping works, so does packet crafting"));
    else r.checks.push_back(passCheck("jail", "raw-sockets", "denied"));
  }
  if (auto v = get("security.jail.mount_allowed")) {
    if (*v == "1") r.checks.push_back(warnCheck("jail", "mount", "in-jail mount(8) allowed (allow.mount)"));
    else r.checks.push_back(passCheck("jail", "mount", "in-jail mount(8) denied"));
  }
  if (auto v = get("security.jail.chflags_allowed")) {
    if (*v == "1") r.checks.push_back(warnCheck("jail", "chflags", "allowed (allow.chflags) — system immutable flags can be cleared from inside"));
    else r.checks.push_back(passCheck("jail", "chflags", "denied"));
  }
  if (auto v = get("security.jail.sysvipc_allowed"))
    r.checks.push_back(passCheck("jail", "sysvipc", *v == "1" ? "SysV IPC allowed" : "SysV IPC denied"));
  if (auto v = get("security.jail.socket_unixiproute_only"))
    r.checks.push_back(passCheck("jail", "socket-af", *v == "1" ? "unix, inet, inet6 and route sockets only" : "all socket address families allowed (allow.socket_af)"));
  if (auto v = get("security.jail.set_hostname_allowed"))
    r.checks.push_back(passCheck("jail", "set-hostname", *v == "1" ? "jail may change its hostname" : "hostname fixed"));
  if (auto v = get("security.jail.enforce_statfs")) {
    if (*v == "0") r.checks.push_back(warnCheck("jail", "enforce-statfs", "0 — the host's whole mount table is visible from inside"));
    else r.checks.push_back(passCheck("jail", "enforce-statfs", *v + (*v == "2" ? " (only the jail's own mounts visible)" : " (mounts under the jail root visible)")));
  }
  if (auto v = get("security.jail.devfs_ruleset"))
    r.checks.push_back(passCheck("jail", "devfs-ruleset", "ruleset " + *v));
}

void mountChecks(Report &r, const std::vector<Mount> &mounts) {
  if (mounts.empty()) {
    r.checks.push_back(warnCheck("mounts", "mount -p", "no mounts reported"));
    return;
  }
  for (const auto &m : mounts) {
    std::string rw = m.readOnly ? "ro" : "rw";
    if (m.fstype == "nullfs") {
      std::string d = "nullfs " + rw + " from host " + m.special;
      if (!m.readOnly && isWideHostPath(m.special))
        r.checks.push_back(warnCheck("mounts", m.node, d + " — a whole host area, writable"));
      else
        r.checks.push_back(passCheck("mounts", m.node, d));
    } else if (m.fstype == "procfs") {
      r.checks.push_back(warnCheck("mounts", m.node, "procfs — process details of the jail; rarely needed, remove if unused"));
    } else if (m.fstype == "zfs") {
      r.checks.push_back(passCheck("mounts", m.node, "zfs " + rw + " dataset " + m.special));
    } else {
      r.checks.push_back(passCheck("mounts", m.node, m.fstype + " " + rw));
    }
  }
}

void devfsChecks(Report &r, const std::vector<std::string> &names) {
  auto d = classifyDevices(names);
  r.checks.push_back(passCheck("devfs", "entries",
    std::to_string(names.size()) + " in /dev, " + std::to_string(d.other) + " basic (null, zero, random, pts, fd...)"));
  if (!d.gpu.empty())    r.checks.push_back(passCheck("devfs", "gpu",    join(d.gpu, ", ", 8) + " — GPU access (gl)"));
  if (!d.video.empty())  r.checks.push_back(passCheck("devfs", "video",  join(d.video, ", ", 8) + " — camera / video capture"));
  if (!d.sound.empty())  r.checks.push_back(passCheck("devfs", "sound",  join(d.sound, ", ", 8) + " — sound hardware (microphone included)"));
  if (!d.input.empty())  r.checks.push_back(warnCheck("devfs", "input",  join(d.input, ", ", 8) + " — keyboard, mouse or console devices: keystrokes of the host are readable"));
  if (!d.usb.empty())    r.checks.push_back(passCheck("devfs", "usb",    join(d.usb, ", ", 8) + " — USB passthrough"));
  if (!d.serial.empty()) r.checks.push_back(passCheck("devfs", "serial", join(d.serial, ", ", 8) + " — serial ports"));
  if (!d.net.empty())    r.checks.push_back(passCheck("devfs", "net",    join(d.net, ", ", 8) + " — tun/tap (VPN inside the jail)"));
  if (!d.disks.empty())  r.checks.push_back(warnCheck("devfs", "disks",  join(d.disks, ", ", 8) + " — raw disk devices: the host's filesystems are readable"));
  if (!d.raw.empty())    r.checks.push_back(warnCheck("devfs", "raw",    join(d.raw, ", ", 8) + " — host memory / packet-filter devices visible"));
}

void ifaceChecks(Report &r, const std::vector<Iface> &ifaces, const Routes &routes) {
  for (const auto &i : ifaces) {
    std::string d = i.up ? "up" : "down";
    if (!i.inet.empty())  d += ", inet " + join(i.inet, " ");
    if (!i.inet6.empty()) d += ", inet6 " + join(i.inet6, " ", 4);
    r.checks.push_back(passCheck("interfaces", i.name, d));
  }
  if (routes.gw4.empty() && routes.gw6.empty())
    r.checks.push_back(passCheck("interfaces", "default-route", "none — no outbound network"));
  else
    r.checks.push_back(passCheck("interfaces", "default-route",
      (routes.gw4.empty() ? "" : "via " + routes.gw4) +
      (routes.gw6.empty() ? "" : (routes.gw4.empty() ? "via " : ", ") + routes.gw6)));
}

void socketChecks(Report &r, const std::vector<Socket> &listening,
                  const std::vector<std::string> &fsSockets, const std::vector<Mount> &mounts) {
  bool anyInet = false;
  for (const auto &s : listening) {
    if (startsWith(s.proto, "tcp") || startsWith(s.proto, "udp")) {
      anyInet = true;
      r.checks.push_back(passCheck("sockets", "listen " + s.proto + " " + s.local,
        s.command + (s.pid ? " (pid " + std::to_string(s.pid) + ")" : "") + " as " + s.user));
    }
  }
  if (!anyInet)
    r.checks.push_back(passCheck("sockets", "listen", "no inet listeners"));

  std::vector<std::string> local;
  for (const auto &p : fsSockets) {
    const Mount *hm = hostMountFor(p, mounts);
    if (!hm) { local.push_back(p); continue; }
    std::string via = " (nullfs from host " + hm->special + ")";
    if (startsWith(p, "/tmp/.X11-unix/"))
      r.checks.push_back(warnCheck("sockets", p, "host X11 display socket" + via + " — the host display is reachable; x11/mode: nested isolates it"));
    else if (p == "/var/run/dbus/system_bus_socket")
      r.checks.push_back(warnCheck("sockets", p, "host system D-Bus" + via + " — dbus/policy decides what the jail may call"));
    else if (p.find("dbus") != std::string::npos)
      r.checks.push_back(warnCheck("sockets", p, "host D-Bus session bus" + via));
    else if (p.find("wayland") != std::string::npos)
      r.checks.push_back(warnCheck("sockets", p, "host Wayland compositor socket" + via));
    else if (p.find("pulse") != std::string::npos || p.find("pipewire") != std::string::npos)
      r.checks.push_back(passCheck("sockets", p, "host sound server socket" + via));
    else
      r.checks.push_back(warnCheck("sockets", p, "host unix socket reachable" + via));
  }
  if (!local.empty())
    r.checks.push_back(passCheck("sockets", "jail-local", std::to_string(local.size()) + " unix socket(s): " + join(local, " ", 6)));
}

void processChecks(Report &r, const std::vector<Proc> &procs, const std::string &idLine) {
  std::map<std::string, unsigned> perUser;
  std::vector<std::string> cmds;
  for (const auto &p : procs) {
    perUser[p.user]++;
    if (std::find(cmds.begin(), cmds.end(), p.command) == cmds.end()) cmds.push_back(p.command);
  }
  std::string users;
  for (const auto &u : perUser) users += (users.empty() ? "" : ", ") + u.first + ": " + std::to_string(u.second);
  r.checks.push_back(passCheck("processes", "running", std::to_string(procs.size()) + " process(es) — " +
    (users.empty() ? std::string("none") : users) + (cmds.empty() ? "" : "; " + join(cmds, " ", 8))));
  if (!idLine.empty())
    r.checks.push_back(passCheck("processes", "probe-ran-as", idLine));
}

void connectivityChecks(Report &r, const std::map<std::string, std::string> &s,
                        const std::vector<std::string> &nameservers, const HostContext &ctx) {
  r.checks.push_back(passCheck("connectivity", "resolver",
    nameservers.empty() ? "no nameserver in /etc/resolv.conf" : "nameserver " + join(nameservers, " ")));
  if (ctx.offline) {
    r.checks.push_back(passCheck("connectivity", "probes", "skipped (--offline)"));
    return;
  }
  auto sec = [&](const char *k) { auto it = s.find(k); return it == s.end() ? std::string() : it->second; };
  std::string gw = firstLine(sec("gw"));
  if (gw.empty()) {
    r.checks.push_back(passCheck("connectivity", "gateway", "no default route — outbound probes skipped"));
  } else if (s.find("connect") == s.end()) {
    r.checks.push_back(failCheck("probe", "connect", "section missing from the probe output"));
  } else {
    int rc = toInt(sec("connect.rc"), -1);
    std::string text = trim(sec("connect"));
    if (rc == 255) {
      r.checks.push_back(passCheck("connectivity", "gateway", gw + " — not an IPv4 address, connect skipped"));
    } else if (rc == 127 || text.find("not found") != std::string::npos) {
      r.checks.push_back(warnCheck("connectivity", "gateway", gw + " — nc(1) not found in the jail, connect skipped"));
    } else {
      switch (classifyNc(rc, text)) {
      case Reach::Open:
        r.checks.push_back(passCheck("connectivity", "gateway", gw + " — tcp/22 open: the host's sshd answers from inside the jail"));
        break;
      case Reach::Refused:
        r.checks.push_back(passCheck("connectivity", "gateway", gw + " — reachable (tcp/22 refused)"));
        break;
      case Reach::Unreachable:
        r.checks.push_back(passCheck("connectivity", "gateway", gw + " — not reachable (" + firstLine(text) + "); expected when the spec grants no `host` network"));
        break;
      case Reach::Unknown:
        r.checks.push_back(warnCheck("connectivity", "gateway", gw + " — nc(1) result not understood (rc " + std::to_string(rc) + "): " + firstLine(text)));
        break;
      }
    }
  }
  if (s.find("dns") == s.end()) {
    r.checks.push_back(failCheck("probe", "dns", "section missing from the probe output"));
    return;
  }
  int rc = toInt(sec("dns.rc"), -1);
  auto answer = parseLines(sec("dns"));
  std::string first = answer.empty() ? "" : answer[0];
  if (rc == 127 || first.find("not found") != std::string::npos)
    r.checks.push_back(warnCheck("connectivity", "dns", "drill(1) not found in the jail, lookup skipped"));
  else if (rc == 0 && !first.empty() && lower(first).find("error") == std::string::npos)
    r.checks.push_back(passCheck("connectivity", "dns", ctx.dnsName + " -> " + join(answer, " ", 3)));
  else
    r.checks.push_back(warnCheck("connectivity", "dns", "lookup of " + ctx.dnsName + " failed" +
      (first.empty() ? std::string(" (no answer)") : ": " + first) +
      (nameservers.empty() ? " — no nameserver configured" : "")));
}

} // anon

DoctorPure::Report buildReport(const std::string &probeStdout, const HostContext &ctx) {
  Report r;
  auto s = splitSections(probeStdout);
  if (s.empty()) {
    r.checks.push_back(failCheck("probe", "output",
      "no output from the in-jail probe — is /bin/sh present in the jail and the jail running?"));
    return r;
  }
  auto sec = [&](const char *k) { auto it = s.find(k); return it == s.end() ? std::string() : it->second; };
  for (const char *req : {"sysctl", "mount", "ifconfig", "routes", "dev", "sockets", "fssockets", "ps", "resolv"})
    if (s.find(req) == s.end())
      r.checks.push_back(failCheck("probe", req, "section missing from the probe output"));

  auto sysctls = parseSysctl(sec("sysctl"));
  auto mounts  = parseMountP(sec("mount"));
  jailChecks(r, sysctls, ctx);
  if (sysctls.empty() && s.find("sysctl") != s.end())
    r.checks.push_back(failCheck("probe", "sysctl", "sysctl(8) printed nothing usable: " + firstLine(sec("sysctl"))));
  mountChecks(r, mounts);
  devfsChecks(r, parseLines(sec("dev")));
  ifaceChecks(r, parseIfconfig(sec("ifconfig")), parseDefaultRoutes(sec("routes")));
  socketChecks(r, parseSockstat(sec("sockets")), parseLines(sec("fssockets")), mounts);
  processChecks(r, parsePs(sec("ps")), firstLine(sec("id")));
  connectivityChecks(r, s, parseResolvConf(sec("resolv")), ctx);
  return r;
}

} // namespace JailAuditPure
