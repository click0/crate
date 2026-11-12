// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "misc.h"
#include "util.h"
#include "err.h"
#include "locs.h"
#include "runtime_paths_pure.h"   // 1.1.73: rootJailsRoot, runtimeRootMode

#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <iostream>

//
// internals
//

static void createDirectoryIfNeeded(const char *dir, const char *what, mode_t wantMode = 0700) {
  int res;

  // 1.1.34: an unprivileged crate(1) (0755 since 1.0.0) cannot create
  // or chmod the root-owned runtime directory — crated(8) owns it. For
  // a non-root caller only refuse a symlink; a missing directory is not
  // an error here (validate/create/--help never need it, and the
  // commands that do fail later with their own message), and its mode
  // is whatever the operator configured for the privops / control-
  // socket group (crated.conf listen.unix_mode etc.), not 0700.
  const bool privileged = ::geteuid() == 0;
  if (!privileged) {
    struct stat sb;
    if (::lstat(dir, &sb) == 0 && S_ISLNK(sb.st_mode))
      ERR2(STR("check " << what << " directory"),
           what << " directory '" << dir << "' is a symlink, refusing to use it")
    return;
  }

  // first, just try to create it. It might already exist which is ok.
  res = ::mkdir(dir, wantMode);
  if (res == -1 && errno != EEXIST)
    ERR2(STR("create " << what << " directory"), "failed to create the " << what << " directory '" << dir << "': " << strerror(errno))

  // Verify permissions (§20): owned by root, with the mode it must have
  // (jail trees: 0700, so unprivileged users cannot reach jail contents).
  // Use lstat() to detect symlink attacks (CWE-59).
  struct stat sb;
  if (::lstat(dir, &sb) == 0) {
    if (S_ISLNK(sb.st_mode))
      ERR2(STR("check " << what << " directory"),
           what << " directory '" << dir << "' is a symlink, refusing to use it")
    if (sb.st_uid != 0)
      ERR2(STR("check " << what << " directory"),
           what << " directory '" << dir << "' is owned by uid " << sb.st_uid << ", expected root (uid 0)")
    if ((sb.st_mode & 0777) != wantMode) {
      // Try to fix permissions silently
      if (::chmod(dir, wantMode) == -1)
        ERR2(STR("fix " << what << " directory permissions"),
             what << " directory '" << dir << "' has mode " << std::oct << (sb.st_mode & 0777)
             << std::dec << ", expected " << std::oct << wantMode << std::dec
             << ", and chmod failed: " << strerror(errno))
    }
  }
}

// 1.1.73: a jail tree a pre-1.1.73 `crate run` / `crate create` left
// directly in /var/run/crate (a running jail, or an orphan for clean).
static bool hasLegacyJailTrees(const char *runtimeRoot) {
  bool found = false;
  if (DIR *d = ::opendir(runtimeRoot)) {
    while (struct dirent *e = ::readdir(d)) {
      if (!RuntimePathsPure::isLegacyJailTreeName(e->d_name)) continue;
      struct stat st;
      const std::string p = std::string(runtimeRoot) + "/" + e->d_name;
      if (::lstat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) { found = true; break; }
    }
    ::closedir(d);
  }
  return found;
}

//
// interface
//

std::string createJailsDirectoryIfNeeded(const char *subdir) {
  // 1.1.73: /var/run/crate is the runtime root — crated's sockets and the
  // per-user roots live there, so it is searchable (0711) for the users
  // who need them. Root's jail trees moved one level down into
  // /var/run/crate/0 (0700). A jail tree from before 1.1.73 still sitting
  // directly in /var/run/crate keeps it 0700 until it is gone.
  std::string note;
  const bool legacy = ::geteuid() == 0 && hasLegacyJailTrees(Locations::jailDirectoryPath);
  createDirectoryIfNeeded(CSTR(Locations::jailDirectoryPath << subdir), "jails",
                          *subdir ? 0700 : (mode_t)RuntimePathsPure::runtimeRootMode(legacy));
  if (!*subdir) {
    createDirectoryIfNeeded(RuntimePathsPure::rootJailsRoot().c_str(), "root jails", 0700);
    if (legacy)
      note = STR(Locations::jailDirectoryPath << " stays 0700: it still holds jail directories from "
                 "before 1.1.73 (stop those containers, or `crate clean` the orphans) — until then "
                 "unprivileged users cannot reach crated's sockets");
  }
  return note;
}

void createCacheDirectoryIfNeeded() {
  createDirectoryIfNeeded(Locations::cacheDirectoryPath, "cache");
}
