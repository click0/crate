// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Runtime side of the spec registry (0.8.21). File-backed
// {jail name -> .crate path} store. See lib/spec_registry_pure.h
// for the design rationale and file format.
//
// Storage: legacy single-tenant default
//            /var/run/crate/spec-registry.txt
//          rootless per-user (1.0.2+, when privops socket detected)
//            /var/run/crate/<uid>/spec-registry.txt
//

#include "spec_registry_pure.h"

#include <string>
#include <vector>

namespace SpecRegistry {

const std::string &registryPath();
void setPathForTesting(const std::string &p);

// Read the registry file. Missing file returns empty; throws on
// permission / parse errors.
std::vector<SpecRegistryPure::Entry> readAll();

// Atomically insert or replace `name` -> `cratePath`. Idempotent
// if the entry already matches. Validates input via
// SpecRegistryPure before touching the file.
void upsert(const std::string &name, const std::string &cratePath);

// 1.1.69: insert or replace a whole entry — the warm-base form
// (`crate run --warm-base <dataset> --name <name>`) has no crate path.
void upsertEntry(const SpecRegistryPure::Entry &e);

// Atomically remove `name`. No-op if absent.
void remove(const std::string &name);

// Look up a name. Returns the .crate path, or an empty string if not
// found — or if the entry is a warm-base run (no file to hand to
// `crate run -f`; crated's start/restart treat that as unknown).
std::string lookup(const std::string &name);

// 1.1.69: the whole entry (crate path or warm-base dataset). False
// when the name is not registered.
bool lookupEntry(const std::string &name, SpecRegistryPure::Entry &out);

} // namespace SpecRegistry
