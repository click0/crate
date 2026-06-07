// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "jid_owner_registry_pure.h"

#include <atf-c++.hpp>

using JidOwnerRegistryPure::Entry;
using JidOwnerRegistryPure::EntryMap;
using JidOwnerRegistryPure::lookupByName;
using JidOwnerRegistryPure::parse;
using JidOwnerRegistryPure::serialize;

namespace {

EntryMap twoEntries() {
  EntryMap m;
  m[12] = Entry{1000, "web",       "/jails/web"};
  m[37] = Entry{1001, "build-vm",  "/zpool/jails/build_vm"};
  return m;
}

} // namespace

// --- serialize ---

ATF_TEST_CASE_WITHOUT_HEAD(serialize_empty_is_empty_string);
ATF_TEST_CASE_BODY(serialize_empty_is_empty_string) {
  ATF_REQUIRE_EQ(std::string(), serialize(EntryMap{}));
}

ATF_TEST_CASE_WITHOUT_HEAD(serialize_sorts_by_jid_and_terminates);
ATF_TEST_CASE_BODY(serialize_sorts_by_jid_and_terminates) {
  // std::map is keyed by jid, so insertion order is irrelevant — we
  // pin the expected output exactly to lock in the stable form.
  std::string s = serialize(twoEntries());
  ATF_REQUIRE_EQ(std::string("12\t1000\tweb\t/jails/web\n"
                             "37\t1001\tbuild-vm\t/zpool/jails/build_vm\n"),
                 s);
}

// --- parse: happy paths ---

ATF_TEST_CASE_WITHOUT_HEAD(parse_round_trips_serialize);
ATF_TEST_CASE_BODY(parse_round_trips_serialize) {
  auto in = twoEntries();
  EntryMap out; std::string err;
  ATF_REQUIRE(parse(serialize(in), out, err));
  ATF_REQUIRE(err.empty());
  ATF_REQUIRE_EQ(in.size(), out.size());
  ATF_REQUIRE_EQ(in[12].uid,  out[12].uid);
  ATF_REQUIRE_EQ(in[12].name, out[12].name);
  ATF_REQUIRE_EQ(in[12].path, out[12].path);
  ATF_REQUIRE_EQ(in[37].uid,  out[37].uid);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_skips_blank_and_comment_lines);
ATF_TEST_CASE_BODY(parse_skips_blank_and_comment_lines) {
  std::string input =
      "# crate jid->owner registry v1\n"
      "\n"
      "12\t1000\tweb\t/jails/web\n"
      "# inline comment\n"
      "37\t1001\tbuild\t/jails/build\n";
  EntryMap out; std::string err;
  ATF_REQUIRE(parse(input, out, err));
  ATF_REQUIRE_EQ(2u, out.size());
  ATF_REQUIRE_EQ(1000u, out[12].uid);
  ATF_REQUIRE_EQ(1001u, out[37].uid);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_accepts_empty_input);
ATF_TEST_CASE_BODY(parse_accepts_empty_input) {
  EntryMap out; std::string err;
  ATF_REQUIRE(parse("", out, err));
  ATF_REQUIRE(out.empty());
  ATF_REQUIRE(err.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_missing_trailing_newline_still_works);
ATF_TEST_CASE_BODY(parse_missing_trailing_newline_still_works) {
  EntryMap out; std::string err;
  ATF_REQUIRE(parse("9\t100\tapp\t/jails/app", out, err));
  ATF_REQUIRE_EQ(1u, out.size());
  ATF_REQUIRE_EQ("app", out[9].name);
}

// --- parse: fail-closed on malformed input ---

ATF_TEST_CASE_WITHOUT_HEAD(parse_rejects_wrong_column_count);
ATF_TEST_CASE_BODY(parse_rejects_wrong_column_count) {
  EntryMap out = {{99, Entry{1, "pre", "/x"}}};  // sentinel: must be cleared
  std::string err;
  ATF_REQUIRE(!parse("12\t1000\tonly3cols\n", out, err));
  ATF_REQUIRE(out.empty());
  ATF_REQUIRE(!err.empty());

  out = {{99, Entry{1, "pre", "/x"}}}; err.clear();
  ATF_REQUIRE(!parse("12\t1000\ttoo\tmany\tcols\n", out, err));
  ATF_REQUIRE(out.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_rejects_empty_column);
ATF_TEST_CASE_BODY(parse_rejects_empty_column) {
  EntryMap out; std::string err;
  // Empty name column ("") would otherwise produce a useless entry.
  ATF_REQUIRE(!parse("12\t1000\t\t/jails/web\n", out, err));
  ATF_REQUIRE(out.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_rejects_jid_out_of_range);
ATF_TEST_CASE_BODY(parse_rejects_jid_out_of_range) {
  EntryMap out; std::string err;
  ATF_REQUIRE(!parse("0\t1000\tweb\t/jails/web\n", out, err));        // jid=0
  out.clear(); err.clear();
  ATF_REQUIRE(!parse("65536\t1000\tweb\t/jails/web\n", out, err));    // >max
  out.clear(); err.clear();
  ATF_REQUIRE(!parse("abc\t1000\tweb\t/jails/web\n", out, err));      // non-numeric
  out.clear(); err.clear();
  ATF_REQUIRE(!parse("-3\t1000\tweb\t/jails/web\n", out, err));       // negative
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_rejects_duplicate_jid);
ATF_TEST_CASE_BODY(parse_rejects_duplicate_jid) {
  EntryMap out; std::string err;
  // Two entries with the same jid: deduce that the file is corrupt and
  // refuse to load anything rather than silently picking the last one.
  ATF_REQUIRE(!parse("12\t1000\tweb\t/jails/web\n"
                     "12\t1001\tbuild\t/jails/build\n",
                     out, err));
  ATF_REQUIRE(out.empty());
  ATF_REQUIRE(err.find("duplicate") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_error_message_carries_line_number);
ATF_TEST_CASE_BODY(parse_error_message_carries_line_number) {
  EntryMap out; std::string err;
  ATF_REQUIRE(!parse("# header\n"
                     "12\t1000\tweb\t/jails/web\n"
                     "garbage\n",
                     out, err));
  // Line 3 is the offender; the message must say so to give the
  // operator something to grep for in /var/db/crate/jid_owners.tsv.
  ATF_REQUIRE(err.find("line 3") != std::string::npos);
}

// --- lookupByName ---

ATF_TEST_CASE_WITHOUT_HEAD(lookup_by_name_hits);
ATF_TEST_CASE_BODY(lookup_by_name_hits) {
  auto m = twoEntries();
  unsigned jid = 0; Entry e;
  ATF_REQUIRE(lookupByName(m, "web", jid, e));
  ATF_REQUIRE_EQ(12u, jid);
  ATF_REQUIRE_EQ(1000u, e.uid);
  ATF_REQUIRE_EQ("/jails/web", e.path);
}

ATF_TEST_CASE_WITHOUT_HEAD(lookup_by_name_miss);
ATF_TEST_CASE_BODY(lookup_by_name_miss) {
  auto m = twoEntries();
  unsigned jid = 999; Entry e;
  ATF_REQUIRE(!lookupByName(m, "nonexistent", jid, e));
}

ATF_TEST_CASE_WITHOUT_HEAD(lookup_by_name_empty_map);
ATF_TEST_CASE_BODY(lookup_by_name_empty_map) {
  EntryMap m;
  unsigned jid; Entry e;
  ATF_REQUIRE(!lookupByName(m, "web", jid, e));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, serialize_empty_is_empty_string);
  ATF_ADD_TEST_CASE(tcs, serialize_sorts_by_jid_and_terminates);
  ATF_ADD_TEST_CASE(tcs, parse_round_trips_serialize);
  ATF_ADD_TEST_CASE(tcs, parse_skips_blank_and_comment_lines);
  ATF_ADD_TEST_CASE(tcs, parse_accepts_empty_input);
  ATF_ADD_TEST_CASE(tcs, parse_missing_trailing_newline_still_works);
  ATF_ADD_TEST_CASE(tcs, parse_rejects_wrong_column_count);
  ATF_ADD_TEST_CASE(tcs, parse_rejects_empty_column);
  ATF_ADD_TEST_CASE(tcs, parse_rejects_jid_out_of_range);
  ATF_ADD_TEST_CASE(tcs, parse_rejects_duplicate_jid);
  ATF_ADD_TEST_CASE(tcs, parse_error_message_carries_line_number);
  ATF_ADD_TEST_CASE(tcs, lookup_by_name_hits);
  ATF_ADD_TEST_CASE(tcs, lookup_by_name_miss);
  ATF_ADD_TEST_CASE(tcs, lookup_by_name_empty_map);
}
