// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.76: host-side file operations inside a jail tree that never follow
// a symlink the jail made. `crate run` writes /etc/rc.conf, /etc/hostid,
// /etc/resolv.conf, crontabs, the init marker and the X cookies into the
// tree as host root, by path. Util::Fs::writeFile's O_NOFOLLOW guards the
// last component only, so a symlinked DIRECTORY — /etc -> /etc, absolute,
// which resolves against the host's root when the host walks it — sent
// the write to the host's own file. The tree is the jail's to shape: a
// --warm-base clone was written by the source jail's root, and an
// archive can carry any link.
//
// Every call here walks `rel` one component at a time from `root`
// (openat + O_DIRECTORY|O_NOFOLLOW for each directory, O_NOFOLLOW for the
// last component) and refuses "." and "..". `root` itself is the host's
// (followed). Errors throw Exception ("jail tree") naming root + rel.
// Plain POSIX: built into the unit tests (fs_beneath_test).

#pragma once

#include <string>
#include <vector>

#include <sys/types.h>

namespace FsBeneath {

// The components of `rel` ("/etc/rc.conf" or "etc/rc.conf"; repeated
// slashes are skipped). "" when valid, otherwise the reason: empty, only
// slashes, or a "." / ".." component.
std::string splitRelative(const std::string &rel, std::vector<std::string> &parts);

// open(2) of root + rel through the walk; `flags` get O_NOFOLLOW and
// O_CLOEXEC added. Returns the descriptor.
int open(const std::string &root, const std::string &rel, int flags, mode_t mode = 0644);

// Whether rel exists (the last component not followed: a symlink there
// exists). false when a directory on the way is missing; throws when one
// is a symlink.
bool exists(const std::string &root, const std::string &rel);
// Whether rel is a directory (not a symlink to one).
bool isDirectory(const std::string &root, const std::string &rel);

// Regular files only — a FIFO, a device or a directory at rel is refused.
// writeFile creates or truncates; appendFile creates or appends. `mode`
// applies to a file they create.
void writeFile(const std::string &root, const std::string &rel, const std::string &data, mode_t mode = 0644);
void appendFile(const std::string &root, const std::string &rel, const std::string &data, mode_t mode = 0644);

// Replace rel with a copy of a regular file: whatever non-directory is
// at rel (a symlink included) is removed, the copy is created O_EXCL,
// then given `mode` and, unless uid is (uid_t)-1, uid:gid. copyIn's
// source is a host path (followed); copyWithin's is another path of the
// same tree, walked like rel.
void copyIn(const std::string &hostSrc, const std::string &root, const std::string &rel,
            mode_t mode, uid_t uid = (uid_t)-1, gid_t gid = (gid_t)-1);
void copyWithin(const std::string &root, const std::string &srcRel, const std::string &dstRel,
                mode_t mode, uid_t uid = (uid_t)-1, gid_t gid = (gid_t)-1);
// A regular file of the tree to a host path (created or truncated 0644;
// the host path's last component is not followed either).
void copyOut(const std::string &root, const std::string &rel, const std::string &hostDst);

void chown(const std::string &root, const std::string &rel, uid_t uid, gid_t gid);
void chmod(const std::string &root, const std::string &rel, mode_t mode);
// A non-directory.
void unlink(const std::string &root, const std::string &rel);
// mkdir -p: missing components are created with `mode`; existing ones
// must be directories (not symlinks to one).
void mkdirs(const std::string &root, const std::string &rel, mode_t mode);

}
