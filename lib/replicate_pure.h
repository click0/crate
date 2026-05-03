// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for `crate replicate <jail> --to <ssh-remote>`. Streams
// a ZFS snapshot of the jail's dataset to a remote host via
// `zfs send | ssh ... 'zfs recv'`. Reuses lib/backup_pure.cpp for
// snapshot naming + plan choice; this module owns the SSH side.
//
// Operators MUST be able to drive the ssh hop themselves:
//   * --ssh-port N                 (the most common one — non-22)
//   * --ssh-key /path/to/id_ed25519 (specify key, not from agent)
//   * --ssh-config /path/to/cfg     (custom ssh_config file)
//   * --ssh-opt KEY=VAL             (pass-through `-o` for any option,
//                                    repeatable: StrictHostKeyChecking,
//                                    UserKnownHostsFile, BatchMode,
//                                    ConnectTimeout, ProxyJump, ...).
//
// The `--ssh-opt` form is a deliberate escape hatch — we don't want
// to enumerate every OpenSSH option in the CLI surface.
//

#include <string>
#include <vector>

namespace ReplicatePure {

// --- Validators ---

// Validate the `--to` argument. Accepts:
//   user@host
//   host
//   user@host.with.dots
//   user@10.0.0.5
// Returns "" on success. Hostname follows RFC 1123 labels; user
// is alnum + `._-` (no whitespace, no shell metacharacters).
std::string validateSshRemote(const std::string &remote);

// Validate one --ssh-opt KEY=VAL string. Rules:
//   * KEY: alnum, length 1..64
//   * '=' is required and exactly one occurrence is the separator
//   * VAL: any printable ASCII except whitespace, control chars,
//          and shell metacharacters (`'` `"` `;` `` ` `` `$` `|`
//          `&` `<` `>` `\\`)
//   * total length ≤ 256 chars
// Returns "" on success.
std::string validateSshOpt(const std::string &kv);

// Validate an --ssh-key path: absolute, no `..`, no shell metas.
std::string validateSshKey(const std::string &path);

// Validate the destination ZFS dataset (e.g. tank/jails/foo). ZFS
// dataset names accept alnum + `._-:/`; `:` is reserved for
// snapshot/bookmark separators in some tools, so we reject it
// here. No `/.`, no leading/trailing `/`.
std::string validateDestDataset(const std::string &ds);

// --- Spec ---

struct SshSpec {
  std::string user;       // optional; empty if --to was just "host"
  std::string host;
  unsigned port = 0;       // 0 = ssh default (22)
  std::string identityFile; // --ssh-key
  std::string configFile;   // --ssh-config
  std::vector<std::string> extraOpts; // raw KEY=VAL pairs from --ssh-opt
};

struct ReplicateRequest {
  // Source side (local)
  std::string sourceDataset;        // pool/jails/foo
  std::string currSnapshotSuffix;   // backup-2026-05-03T...
  std::string prevSnapshotSuffix;   // empty = full; else incremental
  // Destination side (remote)
  std::string destDataset;          // tank/jails/foo on remote
  // Transport
  SshSpec ssh;
};

// Parse `user@host` (or just `host`) into ssh.user + ssh.host.
// Returns "" on success; otherwise a one-line reason.
std::string parseSshRemote(const std::string &remote, SshSpec &out);

// Build the ssh argv used as the second stage of the pipeline:
//   /usr/bin/ssh [-p N] [-i KEY] [-F CFG] [-o KEY=VAL ...] user@host
//   <remoteCommand>
// `remoteCommand` is passed as a single argv element so ssh shells
// it out remotely as one string.
std::vector<std::string> buildSshArgv(const SshSpec &ssh,
                                      const std::string &remoteCommand);

// Build the remote command string that runs on the destination:
//   "zfs recv <destDataset>"
// Returned as a single shell string because ssh concatenates argv
// after the host with a space and then passes it to the remote
// shell. Caller must ensure destDataset is validated.
std::string buildRemoteRecvCommand(const std::string &destDataset);

// Build the full pipeline:
//   stage 0: zfs send [-i prev] curr
//   stage 1: ssh [opts] user@host  "zfs recv dest"
// Returns the list of argv-vectors as Util::execPipeline expects.
std::vector<std::vector<std::string>>
buildReplicationPipeline(const ReplicateRequest &r);

} // namespace ReplicatePure
