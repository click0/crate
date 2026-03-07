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

// Get a single string parameter from a jail identified by JID.
// Returns empty string on failure.
std::string getJailParam(int jid, const std::string &paramName);

// Get jail JID by name; returns -1 if not found.
int getJidByName(const std::string &name);

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

}
