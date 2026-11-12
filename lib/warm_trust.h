// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.75: the trusted spec of a warm template, kept outside every jail
// tree (WarmPure::trustedStoreDir, keyed by the template dataset's guid).
// `crate run --warm-base` reads the spec and the thin-jail manifest from
// here instead of the clone, whose +CRATE.SPEC / +CRATE.THIN the source
// jail's root could have rewritten. Root only.

#pragma once

#include <string>

namespace WarmTrust {

struct Spec {
  std::string spec;          // +CRATE.SPEC
  bool        haveThin = false;
  std::string thin;          // +CRATE.THIN (base/mode: host-ro)
};

// The dataset's ZFS guid; throws.
std::string datasetGuid(const std::string &dataset);

// +CRATE.SPEC and +CRATE.THIN of a plain (xz) .crate archive; throws when
// the archive has no spec or is encrypted.
Spec fromArchive(const std::string &crateFile);

// The store entry of a template guid; false when there is none.
bool fromStore(const std::string &guid, Spec &out);

// Write (replace) the store entry of a template guid; throws.
void toStore(const std::string &guid, const Spec &s);

// For `crate run --warm-base <dataset>`: the store paths of its entry
// (thinPath is "" when the template is not a thin jail). Throws, naming
// `crate template trust`, when the template has no entry.
void storePathsFor(const std::string &dataset, std::string &specPath, std::string &thinPath);

}
