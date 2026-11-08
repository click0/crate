// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// 1.1.59: per-application profiles — `crate run <name>` without -f
// (TODO §17.2, firejail's /etc/firejail/<app>.profile +
// ~/.config/firejail/<app>.local).
//
// A profile is an ordinary spec file found by NAME in, first match wins:
//
//   ~/.config/crate/profiles/<name>.yml           the operator's own
//   /usr/local/share/crate/profiles/<name>.yml    site-local, root-owned
//   /usr/local/share/examples/crate/<name>.yml    shipped with crate
//
// The shipped examples double as the profile set, so `crate run firefox`
// works out of the box without a second copy of 50 files. An optional
//
//   ~/.config/crate/profiles/<name>.local.yml
//
// is merged ON TOP of the profile (maps deep-merged, lists appended,
// scalars replaced), the merged spec is written to
// ~/.local/share/crate/profiles/<name>.yml and built into
// ~/.local/share/crate/profiles/<name>.crate on first use; the build is
// redone when the merged text, the --var values or the crate version
// change (1.1.71; before, when a source file was newer). The
// jail is named after the profile (the .crate file stem), as with -f.
//
// Policy for the .local: it may add packages, options, shares under the
// operator's home, limits, run arguments — but it may not loosen the
// isolation the profile author chose. Hence a .local may not contain the
// keys in forbiddenLocalKeys() (security_advanced, dbus, base, scripts,
// encrypted, socket_proxy, devices, the allow/securelevel/statfs keys of
// security, ipc/raw_sockets, ipc/sysvipc, zfs/datasets; 1.1.71: in either
// spelling, no key twice) and its dirs/share and
// files/share host paths must live under $HOME. Root-owned profile
// directories are not subject to the policy: whoever writes there owns
// the host anyway.
//
// This file is yaml-free so the rules are unit-testable on Linux; the
// YAML walk and the merge live in lib/profile.cpp.
//

#include <map>
#include <string>
#include <vector>

namespace ProfilePure {

// A profile name must be a valid jail name ([A-Za-z0-9._-], 1..128, not
// starting with '-' or '.') — it becomes the .crate stem and the jail
// name — and must not end in ".local" (reserved for the overlay file).
std::string validateProfileName(const std::string &name);

// Candidate spec paths for `name`, highest priority first.
std::vector<std::string> specSearchPaths(const std::string &home, const std::string &name);

// ~/.config/crate/profiles/<name>.local.yml
std::string localOverridePath(const std::string &home, const std::string &name);

// ~/.local/share/crate/profiles — merged specs and built crates.
std::string buildDir(const std::string &home);
std::string cratePath(const std::string &home, const std::string &name);
std::string mergedSpecPath(const std::string &home, const std::string &name);

// Spec key paths a .local overlay may not contain: "dbus" (top level) or
// "security/securelevel" (nested), in the '_' spelling.
const std::vector<std::string> &forbiddenLocalKeys();
// 1.1.71: '-' -> '_' (the parser takes `socket-proxy` for `socket_proxy`).
std::string normaliseKey(const std::string &key);
// "" when the key path ({"security", "securelevel"}; any spelling) is
// allowed in a .local, otherwise the reason.
std::string checkLocalKeyPath(const std::vector<std::string> &path);
// checkLocalKeyPath({key}).
std::string checkLocalTopLevelKey(const std::string &key);
// 1.1.71: the keys of one map of the .local, in file order: a key given
// twice (in either spelling) is refused — yaml-cpp's node["share"]
// answers with the first, while the merge and the parser take both.
std::string checkLocalDuplicateKeys(const std::vector<std::string> &keys, const std::string &where);

// The HOST side of a dirs/share or files/share entry in a .local: "$HOME",
// "$HOME/<...>" (crate's own substitution, Util::pathSubstituteVarsInPath)
// or an absolute path equal to or under `home`. No "..", no "~" (crate
// does not expand it), nothing relative. "" when acceptable.
std::string checkLocalShareHostPath(const std::string &hostPath, const std::string &home);

// 1.1.71: the cache is keyed by content, not by mtime. Until 1.1.70 the
// .crate was rebuilt only when the profile or the .local was NEWER than
// it (whole seconds), so a removed .local, another spec winning the
// search order, a file replaced by an older copy (cp -p, pkg upgrade) or
// other --var values kept the old archive. Now <name>.key holds the
// sha256 of cacheKeyInput(): the merged spec text (which names its
// sources), the --var values and the crate version.
std::string cacheKeyPath(const std::string &home, const std::string &name);
std::string cacheKeyInput(const std::string &mergedSpec,
                          const std::map<std::string, std::string> &vars,
                          const std::string &version);

// RewriteAndBuild: the key changed (or nothing was recorded yet): write
// the merged spec and the key, then build. Build: the merged spec is
// current but the .crate is missing or not newer than it (root has not
// run the printed `crate create` yet). UpToDate: use the .crate.
// Mtimes in nanoseconds, < 0 = the file does not exist.
enum class CacheAction { UpToDate, Build, RewriteAndBuild };
CacheAction cacheAction(long long crateMtimeNs, long long mergedMtimeNs,
                        const std::string &storedKey, const std::string &key);

} // namespace ProfilePure
