// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Tiny pure helpers extracted from lib/run.cpp and lib/run_net.cpp.
// Both are used by lots of jail-spawning code paths but are themselves
// simple string / env-var manipulations.

#pragma once

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
