// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "mount.h"
#include "privops_client.h"
#include "mounts_pure.h"   // 1.1.77: normalizeMountPoint
#include "runtime_paths_pure.h"   // 1.1.77: crateJailRootOf
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
#include <limits.h>   // PATH_MAX (1.1.77)

#include <vector>
#include <iostream>

#define ERR(msg...) ERR2("mount/unmount directories", msg)

Mount::Mount(const char *newFstype, const std::string &newFspath, const std::string &newTarget, int newFlags)
: fstype(newFstype), fspath(MountsPure::normalizeMountPoint(newFspath)), target(newTarget), flags(newFlags)
{
  // 0.9.19: nullfs gets routed through privops when crated's
  // unix-socket listener is available. Detect once at construction;
  // mount/unmount methods choose path based on this cached value.
  // Other fstypes (devfs, unionfs) skip detection — there's no
  // matching privops verb for them, so they keep using nmount(2).
  // 1.1.63: tmpfs too (mount_tmpfs verb; unmount is the generic
  // unmount_nullfs, which is unmount(2) on a path-gated target).
  // 1.1.76: devfs too (mount_devfs) — a rootless `crate run` got EPERM
  // from nmount(2) for the jail's /dev. unionfs still has no verb
  // (`cow:` is refused under rootless before it gets here).
  if (::strcmp(newFstype, "nullfs") == 0 || ::strcmp(newFstype, "tmpfs") == 0 ||
      ::strcmp(newFstype, "devfs") == 0)
    privopsSocket_ = PrivOpsClient::detectSocketPath();
}

Mount::~Mount() {
  if (mounted)
    unmount(false/*doThrow*/); // called after some failure: it will only warn about the failed mount, and the destructor would continue
}

void Mount::addParam(const std::string &name, const std::string &value) {
  params_.emplace_back(name, value);
}

void Mount::mount() {
  // 0.9.19 privops route — nullfs (and 1.1.63 tmpfs) with a detected socket.
  if (!privopsSocket_.empty()) {
    if (::strcmp(fstype, "tmpfs") == 0) {
      auto resp = PrivOpsClient::sendRequest(privopsSocket_,
          PrivOpsClient::buildMountTmpfs(fspath, params_));
      if (!resp.transportError.empty())
        ERR("privops mount_tmpfs '" << fspath << "' transport error: " << resp.transportError)
      if (resp.status >= 400)
        ERR("privops mount_tmpfs '" << fspath << "' failed (status " << resp.status << "): " << resp.body)
      mounted = true;
      return;
    }
    if (::strcmp(fstype, "devfs") == 0) {   // 1.1.76
      auto resp = PrivOpsClient::sendRequest(privopsSocket_,
          PrivOpsClient::buildMountDevfs(fspath));
      if (!resp.transportError.empty())
        ERR("privops mount_devfs '" << fspath << "' transport error: " << resp.transportError)
      if (resp.status >= 400)
        ERR("privops mount_devfs '" << fspath << "' failed (status " << resp.status << "): " << resp.body)
      mounted = true;
      return;
    }
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

  // 1.1.77: nmount(2) follows a symlink anywhere in fspath, and the jail
  // tree can hold one (a --warm-base clone, an archive, the jail's own
  // processes — the shares are mounted after /etc/rc ran): a link on
  // the way put the mount over a host directory. The mount point must
  // resolve to itself — the rule crated has applied to the same mounts
  // under rootless since 1.1.35. (Checked here, then used by path: a
  // jail process swapping a component in between still wins; TODO §2.)
  // Only the part inside the jail is the jail's to shape: the way to the
  // jail root is the host's and is taken as it resolves (a host whose
  // /var or /var/run is a symlink still mounts).
  {
    char real[PATH_MAX];
    if (::realpath(fspath.c_str(), real) == nullptr)
      ERR("mount point '" << fspath << "': " << strerror(errno))
    std::string expect = fspath;
    const std::string jailRoot = RuntimePathsPure::crateJailRootOf(fspath);
    if (!jailRoot.empty()) {
      char realRoot[PATH_MAX];
      if (::realpath(jailRoot.c_str(), realRoot) == nullptr)
        ERR("jail root '" << jailRoot << "': " << strerror(errno))
      expect = std::string(realRoot) + fspath.substr(jailRoot.size());
    }
    if (expect != real)
      ERR("mount point '" << fspath << "' resolves to '" << real
          << "': a symlink on the way is not followed")
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
  for (auto &kv : params_)   // 1.1.63: tmpfs size/uid/gid/mode
    param(kv.first.c_str(), (void*)kv.second.c_str(), (size_t)-1);
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
