// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "mount.h"
#include "privops_client.h"
#include "util.h"
#include "err.h"
#include <rang.hpp>

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <vector>
#include <iostream>

#define ERR(msg...) ERR2("mount/unmount directories", msg)

Mount::Mount(const char *newFstype, const std::string &newFspath, const std::string &newTarget, int newFlags)
: fstype(newFstype), fspath(newFspath), target(newTarget), flags(newFlags)
{
  // 0.9.19: nullfs gets routed through privops when crated's
  // unix-socket listener is available. Detect once at construction;
  // mount/unmount methods choose path based on this cached value.
  // Other fstypes (devfs, unionfs) skip detection — there's no
  // matching privops verb for them, so they keep using nmount(2).
  if (::strcmp(newFstype, "nullfs") == 0)
    privopsSocket_ = PrivOpsClient::detectSocketPath();
}

Mount::~Mount() {
  if (mounted)
    unmount(false/*doThrow*/); // called after some failure: it will only warn about the failed mount, and the destructor would continue
}

void Mount::mount() {
  // 0.9.19 privops route — only for nullfs with a detected socket.
  if (!privopsSocket_.empty()) {
    bool readOnly = (flags & MNT_RDONLY) != 0;
    auto resp = PrivOpsClient::sendRequest(privopsSocket_,
        PrivOpsClient::buildMountNullfs(target, fspath, readOnly));
    if (!resp.transportError.empty())
      ERR("privops mount_nullfs '" << target << "' on '" << fspath
          << "' transport error: " << resp.transportError)
    if (resp.status >= 400)
      ERR("privops mount_nullfs '" << target << "' on '" << fspath
          << "' failed (status " << resp.status << "): " << resp.body)
    mounted = true;
    return;
  }

  // Legacy nmount(2) path — unchanged from pre-0.9.19.
  std::vector<struct iovec> iov;
  auto param = [&iov](const char *name, void *val, size_t len) {
    auto i = iov.size();
    iov.resize(i + 2);
    iov[i].iov_base = ::strdup(name);
    iov[i].iov_len = ::strlen(name) + 1;
    i++;
    iov[i].iov_base = val;
    iov[i].iov_len = len == (size_t)-1 ?
                       val != nullptr ?
                         strlen((const char*)val) + 1
                         :
                         0
                       :
                       len;
  };
  char errmsg[255] = {0};
  errmsg[0] = '\0';
  param("fstype", (void*)fstype,         (size_t)-1);
  param("fspath", (void*)fspath.c_str(), (size_t)-1);
  if (!target.empty())
    param("target", (void*)target.c_str(), (size_t)-1);
  param("errmsg", errmsg,                sizeof(errmsg));
  int res = ::nmount(&iov[0], iov.size(), flags);
  // Free strdup'd names BEFORE checking error — prevents leak if ERR throws
  for (unsigned i = 0; i < iov.size(); i += 2)
    ::free(iov[i].iov_base);
  if (res != 0)
    ERR("nmount of '" << target << "' on '" << fspath << "' failed: " << strerror(errno) << (errmsg[0] ? STR(" (" << errmsg << ")") : ""))
  mounted = true;
}

void Mount::unmount(bool doThrow) {
  // 0.9.19 privops route.
  if (!privopsSocket_.empty()) {
    auto resp = PrivOpsClient::sendRequest(privopsSocket_,
        PrivOpsClient::buildUnmountNullfs(fspath, /*force=*/false));
    if (!resp.transportError.empty() || resp.status >= 400) {
      auto msg = resp.transportError.empty()
                   ? std::to_string(resp.status) + ": " + resp.body
                   : resp.transportError;
      if (doThrow)
        ERR("privops unmount_nullfs '" << fspath << "' failed: " << msg)
      else
        WARN("privops unmount_nullfs '" << fspath << "' failed: " << msg)
    }
    mounted = false;
    return;
  }

  // Legacy unmount(2) path.
  int res = ::unmount(fspath.c_str(), 0/*flags*/);
  if (res == -1) {
    if (doThrow)
      ERR("unmount of '" << fspath << "' failed: " << strerror(errno))
    else
      WARN("unmount of '" << fspath << "' failed: " << strerror(errno))
  }
  mounted = false;
}
