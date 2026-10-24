// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure half of `crate audit <target>` (1.1.61, TODO §17.4 — firejail
// `--audit`): what a running container can actually reach, seen from
// the INSIDE.
//
// `crate doctor` looks at the host. `crate audit` runs one /bin/sh
// probe script inside the jail (exec_in_jail; root or the privops
// socket) and turns its output into the same Check/Report model that
// doctor renders — a categorised table or `-j` JSON, exit code 0/1/2.
//
// The probe uses base-system tools only (mount, ifconfig, netstat,
// sysctl, ls, find, sockstat, ps, nc, drill) and prints sections
// separated by "@@<name>" marker lines. Everything that runs here is
// string parsing of that output, so the whole pipeline is unit-tested
// on Linux. lib/jail_audit.cpp owns the jail lookup, the host-side
// sysctls and the exec.
//

#include "doctor_pure.h"

#include <map>
#include <string>
#include <vector>

namespace JailAuditPure {

// --- The probe ---

// Section names printed by the script, in order. "@@rc=N" lines inside
// a section land in sections["<name>.rc"].
//   id, sysctl, mount, ifconfig, routes, dev, sockets, fssockets, ps,
//   resolv, gw, connect, dns
//
// `dnsName` is the name the in-jail resolver is asked for (validated
// by the caller: hostname charset only — it is pasted into the script).
// With `offline` the two active probes (one TCP connect to the default
// gateway, one DNS lookup) are left out.
std::string probeScript(bool offline, const std::string &dnsName);

// Split the probe's stdout into sections. A line "@@name" starts a
// section; "@@name arg" starts it and stores arg as its first line;
// "@@rc=N" stores N under "<current>.rc". Text before the first marker
// is ignored.
std::map<std::string, std::string> splitSections(const std::string &out);

// --- Parsers for the individual sections ---

struct Mount {
  std::string special;    // host path (nullfs), dataset (zfs), fs name (devfs, tmpfs...)
  std::string node;       // mount point inside the jail
  std::string fstype;
  std::string opts;       // "rw", "ro,nosuid", ...
  bool readOnly = false;
};
// `mount -p` (fstab format, whitespace separated).
std::vector<Mount> parseMountP(const std::string &text);

struct Iface {
  std::string name;
  bool up = false;
  std::vector<std::string> inet;    // addresses only (no netmask)
  std::vector<std::string> inet6;   // scope suffix (%ifname) stripped
};
// `ifconfig -a`.
std::vector<Iface> parseIfconfig(const std::string &text);

struct Routes {
  std::string gw4;   // gateway of the IPv4 default route ("" = none)
  std::string gw6;   // same for IPv6
};
// `netstat -rn` (both families concatenated).
Routes parseDefaultRoutes(const std::string &text);

// `ls -1 DIR` / `find ... -type s`: one name per line, blanks dropped.
std::vector<std::string> parseLines(const std::string &text);

struct Socket {
  std::string user;
  std::string command;
  int         pid = 0;
  std::string proto;    // tcp4, tcp6, udp4, udp6, stream, dgram, seqpac
  std::string local;    // "*:80", "127.0.0.1:53", "/var/run/log"
  std::string foreign;  // "" for listeners / unix
};
// `sockstat -l` (header line skipped).
std::vector<Socket> parseSockstat(const std::string &text);

// `sysctl -e NAME...` ("name=value") and the default "name: value" form.
// security.jail.param.* (parameter descriptors, not values) are dropped.
std::map<std::string, std::string> parseSysctl(const std::string &text);

struct Proc {
  std::string user;
  int         pid = 0;
  std::string command;
};
// `ps -axo user=,pid=,ucomm=`.
std::vector<Proc> parsePs(const std::string &text);

// Nameservers from /etc/resolv.conf.
std::vector<std::string> parseResolvConf(const std::string &text);

// --- Classification ---

enum class Reach { Open, Refused, Unreachable, Unknown };
// `nc -z -w 3 HOST PORT 2>&1` exit status + text.
Reach classifyNc(int rc, const std::string &text);
const char *reachLabel(Reach r);

struct DeviceClasses {
  std::vector<std::string> gpu;     // dri, drm*, nvidia*
  std::vector<std::string> video;   // video*
  std::vector<std::string> sound;   // dsp*, mixer*, sndstat, audio*, midi*
  std::vector<std::string> input;   // input, kbd*, ukbd*, atkbd*, kbdmux*, sysmouse, ums*, uhid*, joy*
  std::vector<std::string> usb;     // usb, usbctl, ugen*
  std::vector<std::string> serial;  // cuau*, cuaU*, ttyu*, ttyU*
  std::vector<std::string> disks;   // ada*, da*, nvd*, nda*, md*, cd*, gpt, diskid, ufs, ufsid, label, zvol
  std::vector<std::string> raw;     // mem, kmem, io, pf, bpf*, kvm — host-wide access
  std::vector<std::string> net;     // tun*, tap*, net, netmap
  unsigned other = 0;               // everything else (null, zero, random, pts, fd...)
};
DeviceClasses classifyDevices(const std::vector<std::string> &names);

// A unix socket path seen on the jail's filesystem: is it inside a
// nullfs mount (= a host socket)? Returns the Mount, or nullptr.
const Mount *hostMountFor(const std::string &path, const std::vector<Mount> &mounts);

// Is a nullfs special (host path) a whole system area rather than one
// application directory? "/", "/home", "/usr/home", "/root", "/etc",
// "/usr", "/var", "/usr/local/etc", a user's home root (/home/<u>).
bool isWideHostPath(const std::string &hostPath);

// --- Report ---

struct HostContext {
  std::string jailName;
  int         jid = 0;
  std::string hostHostid;     // host's kern.hostid ("" = unknown)
  std::string hostHostname;   // host's kern.hostname
  bool        offline = false;
  std::string dnsName;        // the name the probe looked up
};

// The whole thing: probe stdout -> checks. Categories (see
// DoctorPure::categoryRank): jail, mounts, devfs, interfaces, sockets,
// processes, connectivity. A probe section that is missing produces a
// FAIL in the "probe" category instead of silence.
DoctorPure::Report buildReport(const std::string &probeStdout, const HostContext &ctx);

} // namespace JailAuditPure
