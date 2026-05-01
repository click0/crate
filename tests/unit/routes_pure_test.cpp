// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "routes_pure.h"

#include <atf-c++.hpp>

#include <string>

using RoutesPure::StatsInput;
using RoutesPure::formatStatsSseEvent;
using RoutesPure::validateSnapshotName;
using RoutesPure::extractStringField;

// --- formatStatsSseEvent ---

ATF_TEST_CASE_WITHOUT_HEAD(stats_sse_basic_shape);
ATF_TEST_CASE_BODY(stats_sse_basic_shape) {
  StatsInput in;
  in.name = "myjail";
  in.jid = 7;
  in.ip = "10.0.0.5";
  in.usage = {
    {"cputime", "120"},
    {"memoryuse", "12345678"},
  };
  auto frame = formatStatsSseEvent(in, 1730000000L);
  // SSE frame must start with "data: " and end with the double newline.
  ATF_REQUIRE(frame.rfind("data: ", 0) == 0);
  ATF_REQUIRE(frame.size() >= 4);
  ATF_REQUIRE_EQ(frame.substr(frame.size() - 2), std::string("\n\n"));
  // All scheduled fields are present.
  ATF_REQUIRE(frame.find("\"name\":\"myjail\"")    != std::string::npos);
  ATF_REQUIRE(frame.find("\"jid\":7")              != std::string::npos);
  ATF_REQUIRE(frame.find("\"ip\":\"10.0.0.5\"")    != std::string::npos);
  ATF_REQUIRE(frame.find("\"ts\":1730000000")      != std::string::npos);
  // Numeric usage values are unquoted.
  ATF_REQUIRE(frame.find("\"cputime\":120")        != std::string::npos);
  ATF_REQUIRE(frame.find("\"memoryuse\":12345678") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(stats_sse_quotes_non_numeric_values);
ATF_TEST_CASE_BODY(stats_sse_quotes_non_numeric_values) {
  StatsInput in;
  in.name = "j";
  in.jid = 1;
  in.ip = "0.0.0.0";
  // RCTL very rarely emits non-numeric, but be defensive.
  in.usage = {{"someflag", "yes"}};
  auto frame = formatStatsSseEvent(in, 0);
  ATF_REQUIRE(frame.find("\"someflag\":\"yes\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(stats_sse_escapes_special_chars_in_name);
ATF_TEST_CASE_BODY(stats_sse_escapes_special_chars_in_name) {
  StatsInput in;
  in.name = "weird\"name\\with\nnewline";
  in.jid = 99;
  in.ip = "1.2.3.4";
  auto frame = formatStatsSseEvent(in, 1);
  // Embedded quote is escaped, not raw.
  ATF_REQUIRE(frame.find("\"name\":\"weird\\\"name\\\\with\\nnewline\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(stats_sse_handles_empty_usage);
ATF_TEST_CASE_BODY(stats_sse_handles_empty_usage) {
  StatsInput in;
  in.name = "j";
  in.jid = 1;
  in.ip = "127.0.0.1";
  auto frame = formatStatsSseEvent(in, 42);
  // No trailing comma before the closing brace.
  ATF_REQUIRE(frame.find(",}\n\n") == std::string::npos);
  ATF_REQUIRE(frame.find("\"ts\":42") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(stats_sse_handles_negative_and_decimal_numbers);
ATF_TEST_CASE_BODY(stats_sse_handles_negative_and_decimal_numbers) {
  StatsInput in;
  in.name = "j"; in.jid = 1; in.ip = "x";
  in.usage = {{"k1", "-7"}, {"k2", "1.5"}, {"k3", "1.2.3"}};
  auto f = formatStatsSseEvent(in, 0);
  // "-7" and "1.5" are numeric. "1.2.3" is NOT numeric, must be quoted.
  ATF_REQUIRE(f.find("\"k1\":-7")      != std::string::npos);
  ATF_REQUIRE(f.find("\"k2\":1.5")     != std::string::npos);
  ATF_REQUIRE(f.find("\"k3\":\"1.2.3\"") != std::string::npos);
}

// --- validateSnapshotName ---

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_name_empty_is_rejected);
ATF_TEST_CASE_BODY(snapshot_name_empty_is_rejected) {
  ATF_REQUIRE(!validateSnapshotName("").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_name_too_long_is_rejected);
ATF_TEST_CASE_BODY(snapshot_name_too_long_is_rejected) {
  std::string name(65, 'a');
  ATF_REQUIRE(!validateSnapshotName(name).empty());
  std::string atLimit(64, 'a');
  ATF_REQUIRE_EQ(validateSnapshotName(atLimit), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_name_reserved_dot_and_dotdot);
ATF_TEST_CASE_BODY(snapshot_name_reserved_dot_and_dotdot) {
  ATF_REQUIRE(!validateSnapshotName(".").empty());
  ATF_REQUIRE(!validateSnapshotName("..").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_name_invalid_chars);
ATF_TEST_CASE_BODY(snapshot_name_invalid_chars) {
  // Forbidden characters include /, @, space, and shell metachars.
  ATF_REQUIRE(!validateSnapshotName("foo/bar").empty());
  ATF_REQUIRE(!validateSnapshotName("foo@bar").empty());
  ATF_REQUIRE(!validateSnapshotName("foo bar").empty());
  ATF_REQUIRE(!validateSnapshotName("foo;rm").empty());
  ATF_REQUIRE(!validateSnapshotName("foo`x`").empty());
  ATF_REQUIRE(!validateSnapshotName("foo$bar").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_name_valid_examples);
ATF_TEST_CASE_BODY(snapshot_name_valid_examples) {
  ATF_REQUIRE_EQ(validateSnapshotName("backup-1"),         std::string());
  ATF_REQUIRE_EQ(validateSnapshotName("v0.6.1"),           std::string());
  ATF_REQUIRE_EQ(validateSnapshotName("auto_2026-05-01"),  std::string());
  ATF_REQUIRE_EQ(validateSnapshotName("a"),                std::string());
  ATF_REQUIRE_EQ(validateSnapshotName("0"),                std::string());
}

// --- extractStringField ---

ATF_TEST_CASE_WITHOUT_HEAD(extract_simple_field);
ATF_TEST_CASE_BODY(extract_simple_field) {
  ATF_REQUIRE_EQ(extractStringField(R"({"name":"backup-1"})", "name"),
                 std::string("backup-1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_field_with_whitespace);
ATF_TEST_CASE_BODY(extract_field_with_whitespace) {
  ATF_REQUIRE_EQ(extractStringField(R"({  "name"  :  "x"  })", "name"),
                 std::string("x"));
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_field_decodes_escapes);
ATF_TEST_CASE_BODY(extract_field_decodes_escapes) {
  ATF_REQUIRE_EQ(extractStringField(R"({"k":"a\"b\\c\nd"})", "k"),
                 std::string("a\"b\\c\nd"));
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_missing_field_returns_empty);
ATF_TEST_CASE_BODY(extract_missing_field_returns_empty) {
  ATF_REQUIRE(extractStringField(R"({"other":"x"})", "name").empty());
  ATF_REQUIRE(extractStringField("", "name").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_non_string_value_returns_empty);
ATF_TEST_CASE_BODY(extract_non_string_value_returns_empty) {
  // Numeric value — we only extract strings.
  ATF_REQUIRE(extractStringField(R"({"name":42})", "name").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_unterminated_string_returns_empty);
ATF_TEST_CASE_BODY(extract_unterminated_string_returns_empty) {
  // Malformed body must not crash and must not return a partial value.
  ATF_REQUIRE(extractStringField(R"({"name":"oops)", "name").empty());
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, stats_sse_basic_shape);
  ATF_ADD_TEST_CASE(tcs, stats_sse_quotes_non_numeric_values);
  ATF_ADD_TEST_CASE(tcs, stats_sse_escapes_special_chars_in_name);
  ATF_ADD_TEST_CASE(tcs, stats_sse_handles_empty_usage);
  ATF_ADD_TEST_CASE(tcs, stats_sse_handles_negative_and_decimal_numbers);
  ATF_ADD_TEST_CASE(tcs, snapshot_name_empty_is_rejected);
  ATF_ADD_TEST_CASE(tcs, snapshot_name_too_long_is_rejected);
  ATF_ADD_TEST_CASE(tcs, snapshot_name_reserved_dot_and_dotdot);
  ATF_ADD_TEST_CASE(tcs, snapshot_name_invalid_chars);
  ATF_ADD_TEST_CASE(tcs, snapshot_name_valid_examples);
  ATF_ADD_TEST_CASE(tcs, extract_simple_field);
  ATF_ADD_TEST_CASE(tcs, extract_field_with_whitespace);
  ATF_ADD_TEST_CASE(tcs, extract_field_decodes_escapes);
  ATF_ADD_TEST_CASE(tcs, extract_missing_field_returns_empty);
  ATF_ADD_TEST_CASE(tcs, extract_non_string_value_returns_empty);
  ATF_ADD_TEST_CASE(tcs, extract_unterminated_string_returns_empty);
}
