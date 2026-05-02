// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "top_pure.h"

#include <atf-c++.hpp>

#include <string>

using TopPure::Row;
using TopPure::ColWidths;
using TopPure::humanCount;
using TopPure::humanBytes;
using TopPure::cpuPercent;
using TopPure::truncateForColumn;
using TopPure::formatHeader;
using TopPure::formatRow;
using TopPure::formatFooter;
using TopPure::formatFrame;
using TopPure::applyRctlOutput;

// --- humanCount ---

ATF_TEST_CASE_WITHOUT_HEAD(humanCount_under_thousand_is_plain);
ATF_TEST_CASE_BODY(humanCount_under_thousand_is_plain) {
  ATF_REQUIRE_EQ(humanCount(0),   std::string("0"));
  ATF_REQUIRE_EQ(humanCount(7),   std::string("7"));
  ATF_REQUIRE_EQ(humanCount(999), std::string("999"));
}

ATF_TEST_CASE_WITHOUT_HEAD(humanCount_thousands_get_K_suffix);
ATF_TEST_CASE_BODY(humanCount_thousands_get_K_suffix) {
  ATF_REQUIRE_EQ(humanCount(1000),   std::string("1.0K"));
  ATF_REQUIRE_EQ(humanCount(12345),  std::string("12.3K"));
  ATF_REQUIRE_EQ(humanCount(999999), std::string("1000K"));
}

ATF_TEST_CASE_WITHOUT_HEAD(humanCount_millions_and_above);
ATF_TEST_CASE_BODY(humanCount_millions_and_above) {
  ATF_REQUIRE_EQ(humanCount(1000000ULL),         std::string("1.0M"));
  ATF_REQUIRE_EQ(humanCount(2500000ULL),         std::string("2.5M"));
  ATF_REQUIRE_EQ(humanCount(1000000000ULL),      std::string("1.0G"));
  ATF_REQUIRE_EQ(humanCount(1234567890123ULL),   std::string("1.2T"));
}

// --- humanBytes ---

ATF_TEST_CASE_WITHOUT_HEAD(humanBytes_under_kib_is_bytes);
ATF_TEST_CASE_BODY(humanBytes_under_kib_is_bytes) {
  ATF_REQUIRE_EQ(humanBytes(0),    std::string("0 B"));
  ATF_REQUIRE_EQ(humanBytes(1023), std::string("1023 B"));
}

ATF_TEST_CASE_WITHOUT_HEAD(humanBytes_kib_through_gib);
ATF_TEST_CASE_BODY(humanBytes_kib_through_gib) {
  ATF_REQUIRE_EQ(humanBytes(1024),         std::string("1.0 KB"));
  ATF_REQUIRE_EQ(humanBytes(1024 * 1024),  std::string("1.0 MB"));
  ATF_REQUIRE_EQ(humanBytes(1024ULL * 1024 * 1024), std::string("1.0 GB"));
  ATF_REQUIRE_EQ(humanBytes(1024ULL * 1024 * 1024 * 1024), std::string("1.0 TB"));
}

ATF_TEST_CASE_WITHOUT_HEAD(humanBytes_intermediate_values);
ATF_TEST_CASE_BODY(humanBytes_intermediate_values) {
  // 1.5 MiB = 1572864 bytes
  ATF_REQUIRE_EQ(humanBytes(1572864), std::string("1.5 MB"));
  // 12.0 MiB exact
  ATF_REQUIRE_EQ(humanBytes(12ULL * 1024 * 1024), std::string("12.0 MB"));
}

// --- cpuPercent ---

ATF_TEST_CASE_WITHOUT_HEAD(cpuPercent_basic);
ATF_TEST_CASE_BODY(cpuPercent_basic) {
  // 1 second of CPU consumed in 1 second wall-clock = 100%
  ATF_REQUIRE(cpuPercent(0, 1, 1.0) == 100.0);
  // Half a second of CPU in 1 second = 50%
  ATF_REQUIRE(cpuPercent(0, 1, 2.0) == 50.0);
  // Two seconds of CPU in 1 second = 200% (multi-core jail)
  ATF_REQUIRE(cpuPercent(0, 2, 1.0) == 200.0);
}

ATF_TEST_CASE_WITHOUT_HEAD(cpuPercent_zero_dt_returns_zero);
ATF_TEST_CASE_BODY(cpuPercent_zero_dt_returns_zero) {
  ATF_REQUIRE(cpuPercent(0, 100, 0.0)  == 0.0);
  ATF_REQUIRE(cpuPercent(0, 100, -1.0) == 0.0);
}

ATF_TEST_CASE_WITHOUT_HEAD(cpuPercent_counter_went_backwards_returns_zero);
ATF_TEST_CASE_BODY(cpuPercent_counter_went_backwards_returns_zero) {
  // Jail restarted between samples — RCTL counter resets to 0.
  // We must report 0%, not a wildly negative or wraparound value.
  ATF_REQUIRE(cpuPercent(100, 5, 1.0) == 0.0);
}

// --- truncateForColumn ---

ATF_TEST_CASE_WITHOUT_HEAD(truncate_shorter_passes_through);
ATF_TEST_CASE_BODY(truncate_shorter_passes_through) {
  ATF_REQUIRE_EQ(truncateForColumn("foo", 5), std::string("foo"));
  ATF_REQUIRE_EQ(truncateForColumn("foo", 3), std::string("foo"));
}

ATF_TEST_CASE_WITHOUT_HEAD(truncate_longer_appends_marker);
ATF_TEST_CASE_BODY(truncate_longer_appends_marker) {
  ATF_REQUIRE_EQ(truncateForColumn("abcdef",   4), std::string("abc~"));
  ATF_REQUIRE_EQ(truncateForColumn("verylong", 5), std::string("very~"));
}

ATF_TEST_CASE_WITHOUT_HEAD(truncate_width_one_emits_marker_only);
ATF_TEST_CASE_BODY(truncate_width_one_emits_marker_only) {
  ATF_REQUIRE_EQ(truncateForColumn("abc", 1), std::string("~"));
}

ATF_TEST_CASE_WITHOUT_HEAD(truncate_zero_width_yields_empty);
ATF_TEST_CASE_BODY(truncate_zero_width_yields_empty) {
  ATF_REQUIRE(truncateForColumn("abc", 0).empty());
  ATF_REQUIRE(truncateForColumn("abc", -3).empty());
}

// --- formatHeader / formatRow ---

ATF_TEST_CASE_WITHOUT_HEAD(formatHeader_contains_all_columns);
ATF_TEST_CASE_BODY(formatHeader_contains_all_columns) {
  ColWidths cw;
  auto h = formatHeader(cw);
  ATF_REQUIRE(h.find("NAME") != std::string::npos);
  ATF_REQUIRE(h.find("JID")  != std::string::npos);
  ATF_REQUIRE(h.find("IP")   != std::string::npos);
  ATF_REQUIRE(h.find("CPU%") != std::string::npos);
  ATF_REQUIRE(h.find("MEM")  != std::string::npos);
  ATF_REQUIRE(h.find("DISK") != std::string::npos);
  ATF_REQUIRE(h.find("PROC") != std::string::npos);
  // No trailing whitespace.
  ATF_REQUIRE(h.empty() || h.back() != ' ');
}

ATF_TEST_CASE_WITHOUT_HEAD(formatRow_aligns_and_humanises);
ATF_TEST_CASE_BODY(formatRow_aligns_and_humanises) {
  ColWidths cw;
  Row r;
  r.name = "myjail";
  r.jid = 42;
  r.ip = "10.0.0.1";
  r.cpuPct = 12.5;
  r.memBytes = 1024 * 1024 * 50; // 50 MB
  r.diskBytes = 1024;
  r.pcount = 7;
  auto line = formatRow(r, cw);
  ATF_REQUIRE(line.find("myjail")    != std::string::npos);
  ATF_REQUIRE(line.find("42")        != std::string::npos);
  ATF_REQUIRE(line.find("10.0.0.1")  != std::string::npos);
  ATF_REQUIRE(line.find("12.5")      != std::string::npos);
  ATF_REQUIRE(line.find("50.0 MB")   != std::string::npos);
  ATF_REQUIRE(line.find("1.0 KB")    != std::string::npos);
  // No trailing whitespace.
  ATF_REQUIRE(line.empty() || line.back() != ' ');
}

ATF_TEST_CASE_WITHOUT_HEAD(formatRow_truncates_overlong_name);
ATF_TEST_CASE_BODY(formatRow_truncates_overlong_name) {
  ColWidths cw; cw.name = 6;
  Row r;
  r.name = "a-very-long-jail-name";
  r.jid = 1;
  r.ip = "x";
  auto line = formatRow(r, cw);
  ATF_REQUIRE(line.find("a-ver~")          != std::string::npos);
  ATF_REQUIRE(line.find("a-very-long-jail") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(formatFooter_aggregates_totals);
ATF_TEST_CASE_BODY(formatFooter_aggregates_totals) {
  std::vector<Row> rows;
  Row a; a.cpuPct = 10.0; a.memBytes = 1024 * 1024;     a.pcount = 3;
  Row b; b.cpuPct = 20.5; b.memBytes = 2 * 1024 * 1024; b.pcount = 5;
  rows.push_back(a);
  rows.push_back(b);
  auto f = formatFooter(rows);
  ATF_REQUIRE(f.find("2 jails") != std::string::npos);
  ATF_REQUIRE(f.find("30.5%")   != std::string::npos);
  ATF_REQUIRE(f.find("3.0 MB")  != std::string::npos);
  ATF_REQUIRE(f.find("PROC 8")  != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(formatFooter_zero_jails);
ATF_TEST_CASE_BODY(formatFooter_zero_jails) {
  std::vector<Row> rows;
  auto f = formatFooter(rows);
  ATF_REQUIRE(f.find("0 jails") != std::string::npos);
  ATF_REQUIRE(f.find("0.0%")    != std::string::npos);
  ATF_REQUIRE(f.find("0 B")     != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(formatFrame_assembles_header_rows_footer);
ATF_TEST_CASE_BODY(formatFrame_assembles_header_rows_footer) {
  ColWidths cw;
  std::vector<Row> rows;
  Row r; r.name = "j1"; r.jid = 1; r.ip = "1.1.1.1";
  rows.push_back(r);
  auto fr = formatFrame(rows, cw);
  // Exactly 3 newline-separated lines: header + 1 row + footer.
  int nl = 0;
  for (char c : fr) if (c == '\n') nl++;
  ATF_REQUIRE_EQ(nl, 2);
  ATF_REQUIRE(fr.find("NAME")    != std::string::npos);
  ATF_REQUIRE(fr.find("j1")      != std::string::npos);
  ATF_REQUIRE(fr.find("1 jails") != std::string::npos);
}

// --- applyRctlOutput ---

ATF_TEST_CASE_WITHOUT_HEAD(applyRctl_picks_known_keys_ignores_others);
ATF_TEST_CASE_BODY(applyRctl_picks_known_keys_ignores_others) {
  Row r;
  std::string input =
    "memoryuse=12345\n"
    "writebps=999\n"
    "maxproc=7\n"
    "unrelated=42\n"
    "garbageline\n";
  applyRctlOutput(input, r);
  ATF_REQUIRE_EQ(r.memBytes,  (uint64_t)12345);
  ATF_REQUIRE_EQ(r.diskBytes, (uint64_t)999);
  ATF_REQUIRE_EQ(r.pcount,    (uint64_t)7);
}

ATF_TEST_CASE_WITHOUT_HEAD(applyRctl_tolerates_empty_and_malformed);
ATF_TEST_CASE_BODY(applyRctl_tolerates_empty_and_malformed) {
  Row r;
  applyRctlOutput("", r);
  ATF_REQUIRE_EQ(r.memBytes, (uint64_t)0);

  // Non-numeric value must be ignored without throwing.
  applyRctlOutput("memoryuse=abc\nwritebps=NaN\n", r);
  ATF_REQUIRE_EQ(r.memBytes,  (uint64_t)0);
  ATF_REQUIRE_EQ(r.diskBytes, (uint64_t)0);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, humanCount_under_thousand_is_plain);
  ATF_ADD_TEST_CASE(tcs, humanCount_thousands_get_K_suffix);
  ATF_ADD_TEST_CASE(tcs, humanCount_millions_and_above);
  ATF_ADD_TEST_CASE(tcs, humanBytes_under_kib_is_bytes);
  ATF_ADD_TEST_CASE(tcs, humanBytes_kib_through_gib);
  ATF_ADD_TEST_CASE(tcs, humanBytes_intermediate_values);
  ATF_ADD_TEST_CASE(tcs, cpuPercent_basic);
  ATF_ADD_TEST_CASE(tcs, cpuPercent_zero_dt_returns_zero);
  ATF_ADD_TEST_CASE(tcs, cpuPercent_counter_went_backwards_returns_zero);
  ATF_ADD_TEST_CASE(tcs, truncate_shorter_passes_through);
  ATF_ADD_TEST_CASE(tcs, truncate_longer_appends_marker);
  ATF_ADD_TEST_CASE(tcs, truncate_width_one_emits_marker_only);
  ATF_ADD_TEST_CASE(tcs, truncate_zero_width_yields_empty);
  ATF_ADD_TEST_CASE(tcs, formatHeader_contains_all_columns);
  ATF_ADD_TEST_CASE(tcs, formatRow_aligns_and_humanises);
  ATF_ADD_TEST_CASE(tcs, formatRow_truncates_overlong_name);
  ATF_ADD_TEST_CASE(tcs, formatFooter_aggregates_totals);
  ATF_ADD_TEST_CASE(tcs, formatFooter_zero_jails);
  ATF_ADD_TEST_CASE(tcs, formatFrame_assembles_header_rows_footer);
  ATF_ADD_TEST_CASE(tcs, applyRctl_picks_known_keys_ignores_others);
  ATF_ADD_TEST_CASE(tcs, applyRctl_tolerates_empty_and_malformed);
}
