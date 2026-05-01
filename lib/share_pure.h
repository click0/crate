// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure decision helpers for file-share materialization.
//
// crate(8) supports `files:` shares between host and jail. Historically these
// were realized via hard links, which fail with EXDEV when host and jail
// reside on different devices/filesystems. This module decides what concrete
// action to take given the observable filesystem state.
//

namespace SharePure {

// Strategy selected for a single file-share entry.
//
// The two operands are the host path and the jail-side path (already
// adjusted to be inside the jail's rootfs).
enum class FileStrategy {
  // Both paths exist on the same device: drop the jail-side stale file
  // and replace it with a hard link to the host file (existing behaviour).
  HardLinkHostToJail,

  // Only the host file exists; the two paths are on the same device:
  // hard-link host -> jail.
  HardLinkHostToJailNew,

  // Only the jail file exists; the two paths are on the same device:
  // hard-link jail -> host (creates the host file).
  HardLinkJailToHost,

  // Cross-device case where the host file exists (or has just been
  // populated by copying from the jail). The jail-side path must be
  // (re)created as an empty placeholder, then a single-file nullfs
  // bind-mount of the host file is overlaid on it.
  NullfsBindHostToJail,

  // Cross-device case, only the jail file exists. The caller must first
  // copy jail -> host (since hard-link would EXDEV), then proceed as if
  // the host file existed all along (NullfsBindHostToJail).
  CopyJailToHostThenBind,

  // Neither side exists — the spec is invalid for this entry.
  Error,
};

// Inputs observable on the filesystem. Computed by the runtime side; this
// function performs no I/O so it can be unit-tested cheaply.
struct FileShareInputs {
  bool hostExists;
  bool jailExists;
  bool sameDevice; // true iff host file and jail-side path share st_dev
};

// Choose the strategy. Pure function: return value depends only on inputs.
FileStrategy chooseFileStrategy(const FileShareInputs &in);

// Human-readable name for diagnostics and tests.
const char *strategyName(FileStrategy s);

} // namespace SharePure
