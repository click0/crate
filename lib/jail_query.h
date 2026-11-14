// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Jail query and exec wrappers using libjail C API.
// Replaces jls(8) parsing with direct jailparam_* calls.
// JailExec provides jail_attach()-based exec with jexec(8) fallback.

#pragma once

#include <optional>
#include <string>
#include <vector>

namespace JailQuery {

struct JailInfo {
  int jid = 0;
  std::string name;
  std::string path;
  std::string hostname;
  std::string ip4;
  bool dying = false;
};

// Query all jails visible to the current process.
// Filters to crate-managed jails if crateOnly is true (checks path prefix).
std::vector<JailInfo> getAllJails(bool crateOnly = false);

// Lookup a specific jail by name (returns nullopt if not found).
std::optional<JailInfo> getJailByName(const std::string &name);

// Lookup a specific jail by JID (returns nullopt if not found).
std::optional<JailInfo> getJailByJid(int jid);

// 1.1.70: what an operator calls a container: the kernel jail name
// (`crate list`: "web_pid4242"), a jid, or the container name `crate run`
// was given ("web" — RunPure::containerNameOfJail: from the kernel name,
// or from the jail directory for a root-path jail the kernel names by
// its jid; dying jails are not considered for it). nullopt when nothing matches, or
// when the container name matches more than one running jail —
// *matches (optional) then says how many did. 1.1.77: crate jails only;
// the container name counts among the caller's (euid's) own jails only;
// a jid that names another jail than the container name is ambiguous
// (RunPure::chooseContainer).
// anyOwner: the container name counts among every tenant's jails. For
// crated only — it runs as root on behalf of its peers, so "the
// caller's own" would be root's; what the peer may reach is the pool
// ACL's to say, on the jail that was found.
std::optional<JailInfo> findContainer(const std::string &target, unsigned *matches = nullptr,
                                      bool anyOwner = false);

// Get a single string parameter from a jail identified by JID.
// Returns empty string on failure.
std::string getJailParam(int jid, const std::string &paramName);

// 0.8.32: getJidByName(name) deleted — was declared and defined
// since 0.2.5 but had zero callers (production paths use
// getJailByName(name)->jid instead, which gives the operator
// the full info struct in the same call). Audit confirmed nothing
// referenced it. The native ::jail_getid(3) call it wrapped is a
// one-liner anyway; if a future caller needs it, re-add then.

}

namespace JailExec {

// Execute a command inside a jail.
// Primary: fork + jail_attach(jid) + execv.
// Fallback: fork + execv(jexec ...) if jail_attach fails.
// Returns raw wait status.
int execInJail(int jid, const std::vector<std::string> &argv,
               const std::string &user = "root",
               const std::string &what = "exec in jail");

// Execute a command inside a jail and capture stdout.
std::string execInJailGetOutput(int jid, const std::vector<std::string> &argv,
                                const std::string &user = "root",
                                const std::string &what = "exec in jail");

// Execute a command inside a jail, throwing on non-zero exit.
void execInJailChecked(int jid, const std::vector<std::string> &argv,
                       const std::string &user = "root",
                       const std::string &what = "exec in jail");

// 1.1.78: the jail's own display for everything this process runs in it
// from now on: `name` is DISPLAY, XAUTHORITY, WAYLAND_DISPLAY or
// XDG_RUNTIME_DIR (any other name is ignored), `value` the jail-side
// value. `crate run` calls it as its GUI setup settles each one, so
// services and hooks see the display the main command gets on its
// env(1) line. Both paths carry them: the in-process one in the
// command's environment, the rootless one in the exec_in_jail request.
void setJailDisplayVar(const std::string &name, const std::string &value);

// 1.1.41: deliver `sig` (pdkill) to every in-jail command this process
// is currently waiting on through the exec_in_jail path. Those
// commands are crated's children, so a terminal SIGINT does not reach
// them on its own. Async-signal-safe (atomics + pdkill); a no-op when
// nothing is in flight or on the in-process (root) path. After a
// forwarded signal the wait gives the command a short grace period
// and then returns a "killed by SIGTERM" status so the caller's
// teardown (rc.shutdown, destroy_jail) proceeds even if the command
// ignores the signal.
void forwardSignalToPrivopsChildren(int sig);

// 1.1.42: a long-running background process inside a jail (GUI
// compositor, wayvnc). stdin is /dev/null, stdout/stderr are inherited.
// Root path: fork + jail_attach + execv, handle = pid. Rootless path:
// exec_in_jail, handle = process descriptor (+ the pid the daemon
// reported). signalSpawned/waitSpawned hide the difference; wait closes
// the descriptor. spawnInJail throws on failure.
struct Spawned {
  pid_t pid = -1;
  int   pd  = -1;
  bool valid() const { return pid > 0; }
};
Spawned spawnInJail(int jid, const std::vector<std::string> &argv,
                    const std::string &user = "root",
                    const std::string &what = "spawn in jail");
void signalSpawned(const Spawned &s, int sig);
int  waitSpawned(Spawned &s);

}
