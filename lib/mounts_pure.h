// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for 1.1.63 (TODO §17.6 — firejail --read-only,
// --private-tmp / --tmpfs, --private-etc):
//
//   dirs:
//       share:
//           - $HOME/Documents:ro             # scalar with the :ro suffix
//           - [$HOME/Music, /mnt/music, ro]  # [jail, host, ro|rw]
//   tmpfs:
//       - /tmp                               # list form: no size limit
//       - $HOME/.cache
//   tmpfs:
//       /tmp: 512m                           # map form: path -> size
//       $HOME/.cache:                        # null = no limit
//   etc:
//       keep: [localtime, hosts, ssl]        # host /etc entries copied into
//                                            # the jail's /etc at create time
//
// Strings only; lib/spec.cpp parses, lib/run.cpp and lib/create.cpp act.
//

#include <string>
#include <utility>
#include <vector>

namespace MountsPure {

// A share entry's ":ro" / ":rw" suffix. Strips it from `path`; returns
// true for ":ro". A path without a suffix is left alone (false).
bool splitRoSuffix(std::string &path);

// A third share-list element: "ro" -> true, "rw" -> false, anything
// else -> err filled, false.
bool parseRoFlag(const std::string &flag, bool &readOnly, std::string &err);

// tmpfs `size`: decimal digits with an optional k/m/g suffix (either
// case), 1..20 chars, value > 0. "" (no limit) is accepted. Returns ""
// when acceptable, otherwise the reason.
std::string validateTmpfsSize(const std::string &size);

// tmpfs mount point as written in the spec: "/..." or "$HOME/...", no
// "." or ".." components, not "/" itself and not one of the directories
// the jail cannot do without (/dev /proc /etc /bin /sbin /lib /libexec
// /usr /usr/local /var/run — the writable layer stays, tmpfs on top of
// them would hide the jail's own files).
std::string validateTmpfsPath(const std::string &path);

// etc/keep entry: one name under /etc (no "/", not "." or "..", no
// whitespace or shell metacharacters, <= 128 chars).
std::string validateEtcKeepName(const std::string &name);

// `path` is `dir` itself or inside it (both absolute, no trailing slash
// on dir).
bool isUnder(const std::string &path, const std::string &dir);

// nmount(2) parameters for one tmpfs mount: {"size", ...}, {"uid", ...},
// {"gid", ...}, {"mode", ...}. Inside the user's home the mount belongs
// to the user with mode 0700; elsewhere root owns it with the sticky
// 01777 of a shared /tmp. Empty strings are left out.
std::vector<std::pair<std::string, std::string>>
tmpfsParams(const std::string &size, bool underHome, unsigned uid, unsigned gid);

// privops-side validators for mount_tmpfs fields.
std::string validateDecimal(const std::string &s, const char *what);   // uid / gid: 1..10 digits
std::string validateOctalMode(const std::string &mode);                // 3..5 octal digits

} // namespace MountsPure
