// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Tiny pure helpers extracted from lib/run.cpp and lib/run_net.cpp.
// Both are used by lots of jail-spawning code paths but are themselves
// simple string / env-var manipulations.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace RunPure {

// Render argv as a single shell-safe space-separated string.
// Used to log the original command line.
std::string argsToString(int argc, char **argv);

// Read CRATE_* env var, parse as unsigned, fall back to default on
// missing or unparseable value.
unsigned envOrDefault(const char *name, unsigned def);

// 1.1.22: validate a `cron/user` spec field before it is used to build
// the crontab path (`/var/cron/tabs/<user>`) and a `sh -c "chmod ...
// <user>"` string. Both are root-run in the setuid build, so an
// unvalidated value gives path traversal (`../../etc/cron.d/pwn`) and
// shell injection. Constrain to a POSIX-ish username: [A-Za-z0-9._-]
// (1.1.27: '.' allowed, as FreeBSD pw(8) does), 1..32 chars, no leading
// '-', not "."/"..". Empty is REJECTED (1.1.27) — the caller maps an
// empty spec value to the documented default "root" before calling.
// Returns "" on success.
std::string validateCronUser(const std::string &user);

// 1.1.33: `crate run -f <file>.crate` names the jail after the file STEM
// (Util::filePathToBareName). That name becomes the jail directory
// `jail-<name>-<hex>`, the network-lease key, and the kernel jail name, so
// it must obey the same rule as `--name` (WarmPure::validateJailName:
// [A-Za-z0-9._-], 1..NameLimits::kJailName, not "."/".."). It used to be
// taken unchecked: a stem over the limit or with a space / '+' / '@' /
// UTF-8 byte wrote a lease line the lease parser then refused, breaking
// every later `crate run`. Returns "" when the derived name is valid,
// otherwise a message telling the operator to rename the file.
std::string validateCrateFileJailName(const std::string &crateFile);

// 1.1.42: the kernel jail name `crate run` composes is
// "<name>_pid<pid of crate run>". The suffix is the one thing the
// daemon knows about a `crate run` it spawned (it has the child pid),
// so it finds the jail by it to record the owner. Both sides use these
// so the format cannot drift.
std::string jailXnamePidSuffix(long pid);
bool jailXnameHasPid(const std::string &jailName, long pid);

// 1.1.70: the container name a kernel jail name was composed from —
// "web_pid4242" -> "web". The spec registry, /var/run/crate/<name>.crate
// and the control socket's start all speak container names, while the
// kernel (and `crate list`) carry the pid suffix; `crate restart` and
// the daemons' restart looked the kernel name up in the registry and
// never found it. A name without a well-formed "_pid<digits>" tail is
// returned unchanged.
std::string containerNameOf(const std::string &jailName);

// 1.1.72: the <N> of "<name>_pid<N>" (the last well-formed _pid suffix,
// as containerNameOf strips it); false when there is none. A pf anchor
// crate/<name>_pid<N> belongs to the `crate run` with pid N — on the
// root path the jail itself is named by its jid, so `crate clean` cannot
// match anchors against kernel jail names.
bool jailXnamePid(const std::string &jailName, long &pidOut);

// 1.1.74: the ng_bridge node of a netgraph-mode interface:
// "crate_br_<jid>_<seq>" — short enough for NG_NODESIZ (31 chars), only
// characters a netgraph name may hold, and unique per interface.
std::string netgraphBridgeNodeName(int jid, unsigned seq);
// 1.1.74: the node name from `ngctl show <path>` output ("  Name: ngeth0
// Type: eiface ..."); "" when there is none.
std::string ngctlShowName(const std::string &showOutput);

// 1.1.70: the container name of a RUNNING jail. The privops path names
// the jail "<name>_pid<N>" (containerNameOf); the root path creates it
// without a name, so the kernel calls it by its jid ("12") — there the
// jail directory "<root>/jail-<name>-<8 hex>" still carries the name.
// Falls back to `jailName` when neither tells.
std::string containerNameOfJail(const std::string &jailName, const std::string &jailPath);

// 1.1.77: JailQuery::findContainer's choice among the running jails, so
// it can be tested. Only crate jails count (a bastille `web` is never a
// container). Exact kernel name first; then the container name, among
// the CALLER's jails only (root reaches another tenant's jail by its
// kernel name or jid, never because its own `web` is not running);
// then the jid. A jid and a container name that name different jails
// are ambiguous. index is -1 when nothing or more than one jail
// matches; matches says how many did.
struct JailRef {
  int jid = 0;
  std::string name;
  std::string path;
  bool dying = false;
};
struct ContainerChoice {
  int index = -1;
  unsigned matches = 0;
};
ContainerChoice chooseContainer(const std::vector<JailRef> &jails, const std::string &target,
                                uint32_t callerUid);

// 1.1.44: unit number of an epair half ("epair12a" -> 12). False when
// the name is not "epair<N>a|b" — the privops create_epair reply is
// data from another process and used to be substr()'d blindly.
bool epairUnit(const std::string &ifname, unsigned &unitOut);

// 1.1.44: NAT-mode IPv6 point-to-point address for epair pair `num`,
// idx 0 = host side, 1 = jail side. Each pair gets its own /126:
// fd00:cra7:e::<0x100 + 4*num + 1 + idx>, with the offset spread over
// two hextets once it exceeds 0xffff (the old "100 + 2*num" layout put
// pairs n and n+1 into one /126 on two different host interfaces, and
// printed an invalid literal past 0xffff).
std::string epairIp6(unsigned num, unsigned idx);

// 1.1.64 (TODO §17.7, firejail --noroot): the jail account the container
// command runs as.
//
//   run/user absent  -> the operator's own account mirrored into the jail
//                       (same name, uid, gid — what crate always did);
//                       when the operator IS root the mirror would be root,
//                       so the dedicated unprivileged account `crate` is
//                       used instead (created in the jail if missing)
//   run/user: root   -> root inside the jail, explicit opt-in
//   run/user: <name> -> that jail account (a package's `www`, `git`, …,
//                       or one `crate create` / `crate run` creates)
struct RunUser {
  std::string name;
  bool root = false;        // runs as root inside the jail
  bool mirrored = false;    // the operator's own mirrored account
  bool dedicated = false;   // the built-in `crate` account (root operator, no run/user)
};
constexpr const char *kDedicatedRunUser = "crate";
RunUser effectiveRunUser(const std::string &specUser, const std::string &operatorName,
                         unsigned operatorUid);

// true when the account must exist in the jail's passwd before the
// command runs and crate has to make sure of it (not root, not the
// mirrored operator — createUserInJail covers that one).
bool runUserNeedsAccount(const RunUser &u);

// 1.1.71: the jail home the X cookie (.Xauthority / .ICEauthority) moves
// to for `u`, whose passwd home in the jail is `pwHome`; "" when it
// stays where the GUI set-up put it. Under a root `crate run` both copies
// land in the jail's /root (0600 root, /root 0700), which a dedicated or
// named run/user cannot read; root reads it there, and the mirrored
// operator's copy is already in their own home.
std::string runUserCookieHome(const RunUser &u, const std::string &pwHome);

// `run/user` value rule: "" (default), "root", or a pw(8)-style login
// name (letter or '_' first, then [A-Za-z0-9._-], <= 32 chars). Returns
// "" when acceptable, otherwise the reason.
std::string validateRunUser(const std::string &user);

// 1.1.65 (TODO §17.8, firejail --timeout): `run/timeout` — how long the
// container command may run. "90" / "90s" seconds, "15m" minutes, "2h"
// hours; 1 .. kRunTimeoutMax seconds. Returns "" and sets `secondsOut`,
// otherwise the reason ("" / "0" are rejected: omit the key instead).
constexpr unsigned kRunTimeoutMax = 30u * 24 * 3600;   // 30 days
std::string parseRunTimeout(const std::string &text, unsigned &secondsOut);

// The timeout(1) prefix that wraps the command inside the jail:
// `/usr/bin/timeout -k <kRunTimeoutKillAfter> <seconds>` — TERM at the
// deadline, KILL kRunTimeoutKillAfter seconds later. Empty when seconds
// is 0 (no timeout). timeout(1) is in FreeBSD base.
constexpr unsigned kRunTimeoutKillAfter = 10;
constexpr int kRunTimeoutExitCode = 124;   // timeout(1): the deadline was hit
std::vector<std::string> runTimeoutPrefix(unsigned seconds);

// true when `exitCode` of a command wrapped by runTimeoutPrefix(seconds)
// means the deadline fired (false without a timeout: 124 is then the
// program's own code).
bool runTimedOut(unsigned seconds, int exitCode);

}
