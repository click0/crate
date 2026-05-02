// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for `crate top` — a live, htop-style resource monitor
// for crate-managed jails. The runtime side (`lib/top.cpp`) handles
// the polling loop, terminal control, and RCTL probing; everything
// here is pure formatting/arithmetic so it can be unit-tested on
// Linux without a FreeBSD jail.
//

#include <cstdint>
#include <string>
#include <vector>

namespace TopPure {

// One row in the top table. CPU is a percentage in [0, 100*ncpu]
// (so multi-core jails can exceed 100%). memBytes/diskBytes are raw
// counters from RCTL; the renderer humanises them.
struct Row {
  std::string name;
  int jid = 0;
  std::string ip;
  double cpuPct = 0.0;
  uint64_t memBytes = 0;
  uint64_t diskBytes = 0; // RCTL writebps (cumulative bytes since jail start)
  uint64_t pcount = 0;    // process count from RCTL maxproc usage
};

// Column widths used for header + rows. Exposed so tests can assert
// alignment without depending on a hardcoded layout.
struct ColWidths {
  int name = 16;
  int jid = 5;
  int ip = 15;
  int cpu = 7;
  int mem = 10;
  int disk = 10;
  int proc = 5;
};

// Format an integer count like "1234" / "12.3K" / "1.5M" / "2.1G".
// Output never exceeds 6 chars so a single column slot fits easily.
// Negative numbers are not expected here (RCTL counters are uint64).
std::string humanCount(uint64_t n);

// Format a byte count like "0 B" / "999 B" / "1.5 KB" / "12.0 GB".
// Uses base-1024 (KiB/MiB/GiB) but elides the "i" for compactness.
// Output never exceeds 9 chars.
std::string humanBytes(uint64_t bytes);

// Compute a CPU percentage given two RCTL `cputime` samples (in
// seconds, as RCTL emits them) and the wall-clock interval that
// elapsed between them. Returns 0 if dtSeconds <= 0 or the curr
// counter went backwards (jail restarted; treat as no-data).
double cpuPercent(uint64_t prevCpuTime, uint64_t currCpuTime, double dtSeconds);

// Build the header line for the given widths. Right-trimmed (no
// trailing spaces), exactly one space between columns.
std::string formatHeader(const ColWidths &cw);

// Build one body row. Strings longer than the column width are
// truncated; numerics are right-aligned via humanBytes/humanCount.
std::string formatRow(const Row &row, const ColWidths &cw);

// Build the footer line (totals across all rows + jail count).
std::string formatFooter(const std::vector<Row> &rows);

// Build a complete frame: header + N rows + footer, separated by
// "\n". Suitable for writing to stdout after issuing the
// clear-screen escape. No trailing newline.
std::string formatFrame(const std::vector<Row> &rows, const ColWidths &cw);

// Parse the `key=value` lines emitted by `rctl -u jail:<jid>` into
// a Row's CPU/memory/disk/proc fields. The name/jid/ip/cpuPct
// fields are left untouched (callers fill those in from JailQuery).
// Unknown keys are ignored. Always succeeds (best-effort).
void applyRctlOutput(const std::string &rctlOutput, Row &row);

// Truncate a string to width: returns the prefix when shorter, or
// width-1 chars + "…" (UTF-8 ellipsis) when longer. Exposed for
// tests since the truncation rule is easy to get wrong with
// multi-byte characters.
std::string truncateForColumn(const std::string &s, int width);

} // namespace TopPure
