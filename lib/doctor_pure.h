// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for `crate doctor` (0.7.13).
//
// `crate doctor` is a one-shot health-check command: surveys the
// system + crate state, reports a human-readable diagnosis, and
// exits non-zero if something needs operator attention. Aimed at
// the most common ops issues that show up in support tickets:
//
//   - missing kernel modules (vmm/nmdm/if_bridge/dummynet)
//   - external commands not in PATH (zfs/jail/jexec/rctl/ipfw/...)
//   - ZFS pools degraded
//   - audit.log unrotated for too long
//   - jail named in spec but not actually running
//
// This module owns:
//   - the Check / Severity / Report data model
//   - constructors that the runtime calls per finding
//   - text + JSON rendering
//   - exit-code aggregation
//
// All system calls (kldstat, stat(2), command lookup, JailQuery, ...)
// live in lib/doctor.cpp. This file has no system surface so it
// unit-tests cleanly on Linux.
//

#include <string>
#include <vector>

namespace DoctorPure {

enum class Severity { Pass, Warn, Fail };

struct Check {
  std::string category;     // e.g. "kernel" / "command" / "zfs" / "jails"
  std::string name;         // e.g. "vmm" / "/sbin/zfs"
  Severity    severity = Severity::Pass;
  std::string detail;       // human-readable detail (for fails:
                            // include the fix command when possible)
};

struct Report {
  std::vector<Check> checks;
};

// --- Constructors (so the runtime doesn't have to know struct layout) ---

Check passCheck(const std::string &category, const std::string &name,
                const std::string &detail = "");
Check warnCheck(const std::string &category, const std::string &name,
                const std::string &detail);
Check failCheck(const std::string &category, const std::string &name,
                const std::string &detail);

// --- Rendering ---

// Text report. Groups by category, aligned columns, ANSI colour
// when noColor=false. Includes a final summary line:
//   "Summary: 12 PASS, 2 WARN, 1 FAIL"
std::string renderText(const Report &r, bool noColor);

// JSON shape:
//   {
//     "checks": [
//       {"category": "...", "name": "...", "severity": "PASS|WARN|FAIL",
//        "detail": "..."},
//       ...
//     ],
//     "summary": {"pass": 12, "warn": 2, "fail": 1}
//   }
std::string renderJson(const Report &r);

// Exit-code mapping:
//   0  — no warns, no fails
//   1  — at least one warn, no fails
//   2  — at least one fail
int exitCodeFor(const Report &r);

// --- Helpers ---

// Stable text label for a Severity ("PASS" / "WARN" / "FAIL").
const char *severityLabel(Severity s);

// Stable summary triple {pass, warn, fail}.
struct Counts { int pass = 0; int warn = 0; int fail = 0; };
Counts tally(const Report &r);

} // namespace DoctorPure
