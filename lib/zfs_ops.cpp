// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// ZFS operations using libzfs with fallback to zfs(8) commands.

#include "zfs_ops.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#ifdef HAVE_LIBZFS
#include <libzfs.h>
#include <libzfs_core.h>
#include <sys/nvpair.h>
#endif

#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

#include <sstream>
#include <string>

#define ERR(msg...) ERR2("zfs", msg)

namespace ZfsOps {

// ---------------------------------------------------------------------------
// libzfs handle (singleton, lazy init)
// ---------------------------------------------------------------------------

#ifdef HAVE_LIBZFS

static libzfs_handle_t *getHandle() {
  static libzfs_handle_t *h = nullptr;
  if (!h) {
    h = libzfs_init();
    if (!h)
      return nullptr;
    // Register atexit cleanup
    static struct Cleanup {
      ~Cleanup() { if (h) { libzfs_fini(h); h = nullptr; } }
    } cleanup;
  }
  return h;
}

#endif

bool available() {
#ifdef HAVE_LIBZFS
  return getHandle() != nullptr;
#else
  return false;
#endif
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

void snapshot(const std::string &fullSnapName) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    // lzc_snapshot takes an nvlist of snapshots
    nvlist_t *snaps = fnvlist_alloc();
    fnvlist_add_boolean(snaps, fullSnapName.c_str());
    int err = lzc_snapshot(snaps, nullptr, nullptr);
    fnvlist_free(snaps);
    if (err == 0) return;
    // Fall through to command fallback on error
  }
#endif
  Util::execCommand({CRATE_PATH_ZFS, "snapshot", fullSnapName},
    "create ZFS snapshot");
}

void rollback(const std::string &snapName) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, snapName.c_str(), ZFS_TYPE_SNAPSHOT);
    if (zhp) {
      int err = zfs_rollback(zhp, nullptr, B_FALSE);
      zfs_close(zhp);
      if (err == 0) return;
    }
  }
#endif
  Util::execCommand({CRATE_PATH_ZFS, "rollback", snapName},
    "rollback ZFS snapshot");
}

void destroy(const std::string &name) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, name.c_str(),
      ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME | ZFS_TYPE_SNAPSHOT);
    if (zhp) {
      int err = zfs_destroy(zhp, B_FALSE);
      zfs_close(zhp);
      if (err == 0) return;
    }
  }
#endif
  Util::execCommand({CRATE_PATH_ZFS, "destroy", name},
    "destroy ZFS dataset/snapshot");
}

// ---------------------------------------------------------------------------
// Clone
// ---------------------------------------------------------------------------

void clone(const std::string &snapName, const std::string &targetName) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, snapName.c_str(), ZFS_TYPE_SNAPSHOT);
    if (zhp) {
      nvlist_t *props = fnvlist_alloc();
      int err = zfs_clone(zhp, targetName.c_str(), props);
      fnvlist_free(props);
      zfs_close(zhp);
      if (err == 0) return;
    }
  }
#endif
  Util::execCommand({CRATE_PATH_ZFS, "clone", snapName, targetName},
    "clone ZFS snapshot");
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

std::string getMountpoint(const std::string &dataset) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, dataset.c_str(), ZFS_TYPE_FILESYSTEM);
    if (zhp) {
      char buf[PATH_MAX];
      if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, buf, sizeof(buf),
                       nullptr, nullptr, 0, B_FALSE) == 0) {
        std::string result(buf);
        zfs_close(zhp);
        return result;
      }
      zfs_close(zhp);
    }
  }
#endif
  // Fallback: zfs get -H -o value mountpoint <dataset>
  auto output = Util::execCommandGetOutput(
    {CRATE_PATH_ZFS, "get", "-H", "-o", "value", "mountpoint", dataset},
    "get ZFS mountpoint");
  // Strip trailing newline
  while (!output.empty() && (output.back() == '\n' || output.back() == '\r'))
    output.pop_back();
  return output;
}

bool isEncrypted(const std::string &dataset) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, dataset.c_str(), ZFS_TYPE_FILESYSTEM);
    if (zhp) {
      char buf[256];
      int err = zfs_prop_get(zhp, ZFS_PROP_ENCRYPTION, buf, sizeof(buf),
                             nullptr, nullptr, 0, B_FALSE);
      zfs_close(zhp);
      if (err == 0)
        return std::string(buf) != "off" && std::string(buf) != "-";
    }
  }
#endif
  try {
    auto output = Util::execCommandGetOutput(
      {CRATE_PATH_ZFS, "get", "-H", "-o", "value", "encryption", dataset},
      "check ZFS encryption");
    while (!output.empty() && output.back() == '\n') output.pop_back();
    return output != "off" && output != "-";
  } catch (...) {
    return false;
  }
}

bool isKeyLoaded(const std::string &dataset) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, dataset.c_str(), ZFS_TYPE_FILESYSTEM);
    if (zhp) {
      char buf[256];
      int err = zfs_prop_get(zhp, ZFS_PROP_KEYSTATUS, buf, sizeof(buf),
                             nullptr, nullptr, 0, B_FALSE);
      zfs_close(zhp);
      if (err == 0)
        return std::string(buf) == "available";
    }
  }
#endif
  try {
    auto output = Util::execCommandGetOutput(
      {CRATE_PATH_ZFS, "get", "-H", "-o", "value", "keystatus", dataset},
      "check ZFS key status");
    while (!output.empty() && output.back() == '\n') output.pop_back();
    return output == "available";
  } catch (...) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Jail dataset attachment
// ---------------------------------------------------------------------------

void jailDataset(int jid, const std::string &dataset) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, dataset.c_str(), ZFS_TYPE_FILESYSTEM);
    if (zhp) {
      int err = zfs_jail(zhp, jid, B_FALSE);
      zfs_close(zhp);
      if (err == 0) return;
    }
  }
#endif
  Util::execCommand({CRATE_PATH_ZFS, "jail", std::to_string(jid), dataset},
    STR("attach ZFS dataset " << dataset));
}

void unjailDataset(int jid, const std::string &dataset) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, dataset.c_str(), ZFS_TYPE_FILESYSTEM);
    if (zhp) {
      int err = zfs_unjail(zhp, jid);
      zfs_close(zhp);
      if (err == 0) return;
    }
  }
#endif
  Util::execCommand({CRATE_PATH_ZFS, "unjail", std::to_string(jid), dataset},
    STR("detach ZFS dataset " << dataset));
}

// ---------------------------------------------------------------------------
// Mount
// ---------------------------------------------------------------------------

void mount(const std::string &dataset) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, dataset.c_str(), ZFS_TYPE_FILESYSTEM);
    if (zhp) {
      int err = zfs_mount(zhp, nullptr, 0);
      zfs_close(zhp);
      if (err == 0) return;
    }
  }
#endif
  Util::execCommand({CRATE_PATH_ZFS, "mount", dataset}, "mount ZFS dataset");
}

// ---------------------------------------------------------------------------
// Snapshot listing
// ---------------------------------------------------------------------------

#ifdef HAVE_LIBZFS
static int snapshotIterCb(zfs_handle_t *zhp, void *data) {
  auto *list = static_cast<std::vector<SnapshotInfo>*>(data);
  SnapshotInfo info;
  info.name = zfs_get_name(zhp);

  char buf[256];
  if (zfs_prop_get(zhp, ZFS_PROP_USED, buf, sizeof(buf),
                   nullptr, nullptr, 0, B_FALSE) == 0)
    info.used = buf;
  if (zfs_prop_get(zhp, ZFS_PROP_REFERENCED, buf, sizeof(buf),
                   nullptr, nullptr, 0, B_FALSE) == 0)
    info.refer = buf;
  if (zfs_prop_get(zhp, ZFS_PROP_CREATION, buf, sizeof(buf),
                   nullptr, nullptr, 0, B_FALSE) == 0)
    info.creation = buf;

  list->push_back(info);
  zfs_close(zhp);
  return 0;
}
#endif

std::vector<SnapshotInfo> listSnapshots(const std::string &dataset) {
  std::vector<SnapshotInfo> result;

#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, dataset.c_str(), ZFS_TYPE_FILESYSTEM);
    if (zhp) {
      zfs_iter_snapshots(zhp, B_FALSE, snapshotIterCb, &result, 0, 0);
      zfs_close(zhp);
      if (!result.empty()) return result;
    }
  }
#endif

  // Fallback: zfs list -t snapshot -H -o name,used,refer,creation -r <dataset>
  try {
    auto output = Util::execCommandGetOutput(
      {CRATE_PATH_ZFS, "list", "-t", "snapshot", "-H",
       "-o", "name,used,refer,creation", "-r", dataset},
      "list ZFS snapshots");
    std::istringstream is(output);
    std::string line;
    while (std::getline(is, line)) {
      if (line.empty()) continue;
      std::istringstream ls(line);
      SnapshotInfo info;
      ls >> info.name >> info.used >> info.refer;
      std::getline(ls, info.creation);
      // trim leading whitespace
      auto pos = info.creation.find_first_not_of(" \t");
      if (pos != std::string::npos)
        info.creation = info.creation.substr(pos);
      result.push_back(info);
    }
  } catch (...) {}

  return result;
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

void diff(const std::string &snap1, const std::string &snap2, int outFd) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, snap1.c_str(), ZFS_TYPE_SNAPSHOT);
    if (zhp) {
      // zfs_show_diffs writes to outFd
      int err = zfs_show_diffs(zhp, outFd, snap2.c_str(), nullptr, 0);
      zfs_close(zhp);
      if (err == 0) return;
    }
  }
#endif
  // Fallback: zfs diff <snap1> <snap2>, redirect to outFd
  // Use a pipeline that outputs to fd
  auto output = Util::execCommandGetOutput(
    {CRATE_PATH_ZFS, "diff", snap1, snap2}, "ZFS diff");
  if (outFd == STDOUT_FILENO) {
    std::cout << output;
  } else {
    ::write(outFd, output.data(), output.size());
  }
}

// ---------------------------------------------------------------------------
// Send / Recv
// ---------------------------------------------------------------------------

void send(const std::string &snapName, int fd) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, snapName.c_str(), ZFS_TYPE_SNAPSHOT);
    if (zhp) {
      sendflags_t flags = {};
      int err = zfs_send_one(zhp, nullptr, fd, &flags, nullptr);
      zfs_close(zhp);
      if (err == 0) return;
    }
  }
#endif
  // Fallback: zfs send <snap> → pipe to fd
  // This requires redirecting stdout to fd, so use fork
  pid_t pid = ::fork();
  if (pid == 0) {
    if (fd != STDOUT_FILENO) {
      ::dup2(fd, STDOUT_FILENO);
      ::close(fd);
    }
    ::execlp(CRATE_PATH_ZFS, "zfs", "send", snapName.c_str(), nullptr);
    ::_exit(127);
  }
  if (pid > 0) {
    int status;
    ::waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
      ERR("zfs send failed for " << snapName)
  }
}

void recv(const std::string &targetDataset, int fd) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    recvflags_t flags = {};
    int err = lzc_receive(targetDataset.c_str(), nullptr, nullptr, B_FALSE, B_FALSE, fd);
    (void)flags;
    if (err == 0) return;
  }
#endif
  // Fallback: zfs recv <dataset> < fd
  pid_t pid = ::fork();
  if (pid == 0) {
    if (fd != STDIN_FILENO) {
      ::dup2(fd, STDIN_FILENO);
      ::close(fd);
    }
    ::execlp(CRATE_PATH_ZFS, "zfs", "recv", targetDataset.c_str(), nullptr);
    ::_exit(127);
  }
  if (pid > 0) {
    int status;
    ::waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
      ERR("zfs recv failed for " << targetDataset)
  }
}

// ---------------------------------------------------------------------------
// Refquota (disk usage limit per dataset)
// ---------------------------------------------------------------------------

void setRefquota(const std::string &dataset, const std::string &quota) {
#ifdef HAVE_LIBZFS
  auto *h = getHandle();
  if (h) {
    zfs_handle_t *zhp = zfs_open(h, dataset.c_str(), ZFS_TYPE_DATASET);
    if (zhp) {
      int err = zfs_prop_set(zhp, "refquota", quota.c_str());
      zfs_close(zhp);
      if (err == 0) return;
    }
  }
#endif
  // Fallback: zfs set refquota=<quota> <dataset>
  Util::execCommand({CRATE_PATH_ZFS, "set", STR("refquota=" << quota), dataset},
    CSTR("set ZFS refquota " << quota << " on " << dataset));
}

}
