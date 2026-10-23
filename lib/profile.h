// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// 1.1.59: per-application profiles — the yaml-cpp half. Rules and paths
// are in lib/profile_pure.h.
//

#include <yaml-cpp/yaml.h>

#include <string>

class Args;

namespace Profile {

// `crate run <name>`: locate the profile spec, merge the optional
// ~/.config/crate/profiles/<name>.local.yml on top (after checking it
// against the ProfilePure policy), build or refresh
// ~/.local/share/crate/profiles/<name>.crate and return that path for the
// ordinary -f run path. Throws Exception with a one-line reason.
std::string resolveForRun(const Args &args);

// overlay onto base: maps are merged key by key (recursively), sequences
// are appended (an item already present verbatim is not added twice),
// anything else — scalars, or a map meeting a sequence — is replaced by
// the overlay. Neither argument is modified.
YAML::Node mergeYaml(const YAML::Node &base, const YAML::Node &overlay);

// Throws when `overlay` (the parsed .local) contains a forbidden top-level
// key or a dirs/share / files/share host path outside `home`. `path` is
// the file name for the message.
void checkLocalOverlay(const YAML::Node &overlay, const std::string &home, const std::string &path);

// Load basePath (and overlayPath when non-empty), merge, and write the
// result to outPath with a "generated from ..." header, atomically. Used
// by `crate run <profile>` and by `crate create --template` (1.1.59: the
// merged spec is what goes into +CRATE.SPEC, so the template's settings
// reach `crate run`).
void writeMerged(const std::string &basePath, const std::string &overlayPath,
                 const std::string &outPath);

} // namespace Profile
