// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Name-length limits shared by every validator that sees a jail name or a
// string derived from one (1.1.32).
//
// Before this, "jail name" meant 64 chars in warm/backup/migrate, 63 in
// vm-wrap and 200 in privops — so a jail `crate run` could create was
// then refused by `crate backup`, `crate warm` or `crate migrate`. The
// derived limits below were also never checked against each other: the
// network-lease key `jail-<name>-<hex>` was capped at 64, so any name
// longer than ~50 chars produced a lease line the parser later rejected,
// breaking every subsequent `crate run`.
//
// Change kJailName here and the derived limits follow; the static_asserts
// stop them from drifting apart again.

#pragma once

#include <cstddef>

namespace NameLimits {

// User-facing jail / container name: `crate run --name`, backup, warm,
// migrate, `crate vm-wrap --jail`.
constexpr std::size_t kJailName = 128;

// Kernel jail name built by lib/run.cpp as `<name>_pid<getpid()>` and
// validated by the privops plane. Must leave room for the suffix.
constexpr std::size_t kKernelJailName = 200;

// Network-lease key built by lib/run.cpp as
// `jail-<name>-<Util::randomHex(4)>` (4 bytes -> 8 hex chars).
constexpr std::size_t kRunHexChars = 8;
constexpr std::size_t kLeaseName = 5 /*"jail-"*/ + kJailName + 1 /*"-"*/ + kRunHexChars;

// Exported artifact `<kernel jail name>-<unix time>.crate` — a single path
// component, so the filesystem's NAME_MAX is the real ceiling.
constexpr std::size_t kArtifactFile = 255;

static_assert(kKernelJailName >= kJailName + 4 /*"_pid"*/ + 7 /*pid digits*/,
              "kernel jail name must fit <name>_pid<pid>");
static_assert(kArtifactFile >= kKernelJailName + 1 /*"-"*/ + 10 /*unix time*/ + 6 /*".crate"*/,
              "artifact file name must fit <kernel name>-<time>.crate");

}
