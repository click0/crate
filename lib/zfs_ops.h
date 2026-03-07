// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// ZFS operations wrapper using libzfs C API with fallback to zfs(8) commands.
// Compile with HAVE_LIBZFS defined and link -lzfs -lzfs_core -lnvpair
// to use native API; otherwise all operations use fork+exec fallback.

#pragma once

#include <string>
#include <vector>

namespace ZfsOps {

// Whether native libzfs API is available (compile-time check).
bool available();

// Snapshot management
void snapshot(const std::string &fullSnapName);  // e.g. "pool/ds@snap"
void rollback(const std::string &snapName);
void destroy(const std::string &name);           // dataset, snapshot, or clone

// Clone
void clone(const std::string &snapName, const std::string &targetName);

// Properties
std::string getMountpoint(const std::string &dataset);
bool isEncrypted(const std::string &dataset);
bool isKeyLoaded(const std::string &dataset);

// Jail dataset attachment
void jailDataset(int jid, const std::string &dataset);
void unjailDataset(int jid, const std::string &dataset);

// Mount/unmount a dataset
void mount(const std::string &dataset);

// Snapshot listing
struct SnapshotInfo {
  std::string name;    // full name including @
  std::string used;    // human-readable size
  std::string refer;
  std::string creation;
};
std::vector<SnapshotInfo> listSnapshots(const std::string &dataset);

// Snapshot diff (output goes to fd, typically stdout)
void diff(const std::string &snapOrDataset1, const std::string &snapOrDataset2, int outFd);

// ZFS send/recv (stream to/from fd)
void send(const std::string &snapName, int fd);
void recv(const std::string &targetDataset, int fd);

}
