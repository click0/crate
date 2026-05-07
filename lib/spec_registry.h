// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Runtime side of the spec registry (0.8.21). File-backed
// {jail name -> .crate path} store. See lib/spec_registry_pure.h
// for the design rationale and file format.
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

// Atomically remove `name`. No-op if absent.
void remove(const std::string &name);

// Look up a name. Returns empty string if not found.
std::string lookup(const std::string &name);

} // namespace SpecRegistry
