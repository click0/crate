// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include "misc.h"
#include "util.h"
#include "err.h"
#include "locs.h"

#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <iostream>

//
// internals
//

static void createDirectoryIfNeeded(const char *dir, const char *what) {
  int res;

  // first, just try to create it. It might already exist which is ok.
  res = ::mkdir(dir, 0700); // it should be only readable/writable by root
  if (res == -1 && errno != EEXIST)
    ERR2(STR("create " << what << " directory"), "failed to create the " << what << " directory '" << dir << "': " << strerror(errno))

  // Verify permissions (§20): jail directory must be owned by root with mode 0700
  // to prevent unprivileged users from manipulating jail contents
  struct stat sb;
  if (::stat(dir, &sb) == 0) {
    if (sb.st_uid != 0)
      ERR2(STR("check " << what << " directory"),
           what << " directory '" << dir << "' is owned by uid " << sb.st_uid << ", expected root (uid 0)")
    if ((sb.st_mode & 0777) != 0700) {
      // Try to fix permissions silently
      if (::chmod(dir, 0700) == -1)
        ERR2(STR("fix " << what << " directory permissions"),
             what << " directory '" << dir << "' has mode " << std::oct << (sb.st_mode & 0777)
             << std::dec << ", expected 0700, and chmod failed: " << strerror(errno))
    }
  }
}

//
// interface
//

void createJailsDirectoryIfNeeded(const char *subdir) {
  createDirectoryIfNeeded(CSTR(Locations::jailDirectoryPath << subdir), "jails");
}

void createCacheDirectoryIfNeeded() {
  createDirectoryIfNeeded(Locations::cacheDirectoryPath, "cache");
}
