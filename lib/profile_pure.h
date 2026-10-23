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
// redone when the profile or the .local is newer than the .crate. The
// jail is named after the profile (the .crate file stem), as with -f.
//
// Policy for the .local: it may add packages, options, shares under the
// operator's home, limits, run arguments — but it may not loosen the
// isolation the profile author chose. Hence a .local may not contain the
// top-level keys in forbiddenLocalKeys() (security_advanced, dbus, base,
// scripts, encrypted, securelevel, socket_proxy) and its dirs/share and
// files/share host paths must live under $HOME. Root-owned profile
// directories are not subject to the policy: whoever writes there owns
// the host anyway.
//
// This file is yaml-free so the rules are unit-testable on Linux; the
// YAML walk and the merge live in lib/profile.cpp.
//

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

// Top-level spec keys a .local overlay may not contain.
const std::vector<std::string> &forbiddenLocalKeys();
// "" when `key` is allowed in a .local, otherwise the reason.
std::string checkLocalTopLevelKey(const std::string &key);

// The HOST side of a dirs/share or files/share entry in a .local: "$HOME",
// "$HOME/<...>" (crate's own substitution, Util::pathSubstituteVarsInPath)
// or an absolute path equal to or under `home`. No "..", no "~" (crate
// does not expand it), nothing relative. "" when acceptable.
std::string checkLocalShareHostPath(const std::string &hostPath, const std::string &home);

// The .crate must be rebuilt when it is missing (crateMtime < 0) or older
// than the profile or than the .local (localMtime < 0 = no .local).
bool needsRebuild(long crateMtime, long specMtime, long localMtime);

} // namespace ProfilePure
