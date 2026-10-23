// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.58: thin jails on nullfs — `base/mode: host-ro` (TODO §17.1,
// bwrap's `--ro-bind /usr`, the classic FreeBSD thin-jail layout).
//
// Instead of carrying a full copy of the base system, a thin crate holds
// only the WRITABLE layer (/etc /var /root /tmp /home /usr/local, plus
// the +CRATE.* metadata) and `crate run` nullfs-mounts the host's own
// userland directories (/bin /sbin /lib /libexec /rescue /usr/{bin,sbin,
// lib,lib32,libexec,libdata,share,include}) read-only into the jail
// before it starts. Start is a tar of a few MB instead of ~300, the
// archive is tiny, and a host upgrade upgrades every thin jail at its
// next start.
//
// The manifest `+CRATE.THIN` written by `crate create` names the mode,
// the host release the writable layer was extracted from and the exact
// list of host directories to mount, so `crate run` (and an operator
// reading the archive) never has to guess. `crate export` already uses
// --one-file-system (1.1.48), so exporting a running thin jail archives
// the writable layer only and the result is a valid thin crate.
//
// Pure: paths and strings only; create.cpp / run.cpp do the mounting.

#pragma once

#include <string>
#include <utility>
#include <vector>

namespace ThinJailPure {

// Host directories mounted read-only when the spec gives no
// base/host-dirs of its own. /usr itself is NOT in the list: /usr/local
// (pkg installs), /usr/home and /usr/ports stay per-jail and writable.
const std::vector<std::string> &defaultHostDirs();

// Directories that are allowed to be missing on the host (32-bit compat
// libraries and the rescue tools are optional installs): `crate run`
// skips them with a log line instead of failing.
bool isOptionalHostDir(const std::string &dir);

// Validate one base/host-dirs entry: absolute, normalised (no "..", no
// empty or "." components, no trailing slash), not "/" or "/usr" (would
// hide the jail's own /usr/local) and not inside the writable layer
// (/etc /var /tmp /root /home /usr/local /dev /proc /mnt /media).
// Returns "" when acceptable, otherwise the reason.
std::string validateHostDir(const std::string &dir);

// Validate a whole list: each entry + no duplicates + no entry nested in
// another (the inner mount would be shadowed). "" when acceptable.
std::string validateHostDirs(const std::vector<std::string> &dirs);

// Members of base.txz that make up the writable layer; the rest of the
// archive is never extracted for a thin crate. All four are present in
// every release's base.txz ("./etc" "./var" "./root" "./tmp").
const std::vector<std::string> &baseArchiveSkeletonMembers();

// Directories `crate create` makes in the (empty) writable layer so the
// mount targets, devfs and pkg have somewhere to land: /dev /proc /media
// /mnt /home /usr /usr/local, followed by every host dir (mount target).
std::vector<std::string> directoriesToCreate(const std::vector<std::string> &hostDirs);

// Mount plan: {target under jailPath, host source} for each host dir, in
// an order where a parent directory always comes before anything under
// it (plain lexicographic order gives that for absolute paths).
std::vector<std::pair<std::string, std::string>>
mountPlan(const std::string &jailPath, const std::vector<std::string> &hostDirs);

// ---- +CRATE.THIN manifest -------------------------------------------------

struct Manifest {
  std::string mode = "host-ro";          // the only mode today
  std::string osrelease;                 // kern.osrelease at create time
  std::vector<std::string> hostDirs;     // what to mount, in order
};

constexpr const char *kManifestFile = "+CRATE.THIN";
constexpr size_t kManifestMaxBytes = 64 * 1024;

// "# crate thin jail v1\nmode\thost-ro\nosrelease\t14.2-RELEASE-p3\n
//  hostdir\t/bin\n..." — tab separated, one key per line.
std::string serializeManifest(const Manifest &m);

// Strict parse: unknown keys, a mode other than host-ro, an invalid
// host dir, a missing osrelease or an empty dir list are errors (err
// filled, false returned).
bool parseManifest(const std::string &content, Manifest &out, std::string &err);

// Release compatibility of the writable layer (extracted from base.txz
// of `created`) against the running host (`host`): "" when the
// major.minor matches (patch levels may differ freely), otherwise a
// warning text. A different major version gets the stronger wording:
// rc.d scripts and /etc defaults of one major do not always drive the
// binaries of another.
std::string releaseMismatchWarning(const std::string &created, const std::string &host);

// "14.2-RELEASE-p3" -> "14.2"; "15.0-CURRENT" -> "15.0"; "" when the
// string does not start with <digits>.<digits>.
std::string majorMinor(const std::string &osrelease);

} // namespace ThinJailPure
