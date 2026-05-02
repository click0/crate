// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "transfer_pure.h"

#include <atf-c++.hpp>

#include <string>

using TransferPure::validateArtifactName;
using TransferPure::formatExportResponse;
using TransferPure::formatImportResponse;
using TransferPure::sniffArchiveType;
using TransferPure::hexEncode;

// --- validateArtifactName ---

ATF_TEST_CASE_WITHOUT_HEAD(name_empty_is_rejected);
ATF_TEST_CASE_BODY(name_empty_is_rejected) {
  ATF_REQUIRE(!validateArtifactName("").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(name_reserved_dot_and_dotdot_rejected);
ATF_TEST_CASE_BODY(name_reserved_dot_and_dotdot_rejected) {
  ATF_REQUIRE(!validateArtifactName(".").empty());
  ATF_REQUIRE(!validateArtifactName("..").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(name_too_long_rejected);
ATF_TEST_CASE_BODY(name_too_long_rejected) {
  ATF_REQUIRE_EQ(validateArtifactName(std::string(128, 'a')), std::string());
  ATF_REQUIRE(!validateArtifactName(std::string(129, 'a')).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(name_path_traversal_rejected);
ATF_TEST_CASE_BODY(name_path_traversal_rejected) {
  // Slash forbidden — path traversal protection.
  auto err = validateArtifactName("../etc/passwd");
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err.find("traversal") != std::string::npos);
  ATF_REQUIRE(!validateArtifactName("foo/bar").empty());
  ATF_REQUIRE(!validateArtifactName("foo\\bar").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(name_whitespace_rejected);
ATF_TEST_CASE_BODY(name_whitespace_rejected) {
  ATF_REQUIRE(!validateArtifactName("foo bar").empty());
  ATF_REQUIRE(!validateArtifactName("foo\tbar").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(name_metacharacters_rejected);
ATF_TEST_CASE_BODY(name_metacharacters_rejected) {
  ATF_REQUIRE(!validateArtifactName("foo;rm").empty());
  ATF_REQUIRE(!validateArtifactName("foo`x`").empty());
  ATF_REQUIRE(!validateArtifactName("foo$bar").empty());
  ATF_REQUIRE(!validateArtifactName("foo|bar").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(name_typical_archives_accepted);
ATF_TEST_CASE_BODY(name_typical_archives_accepted) {
  ATF_REQUIRE_EQ(validateArtifactName("myapp.crate"),                std::string());
  ATF_REQUIRE_EQ(validateArtifactName("myapp-2026-05-02.crate"),     std::string());
  ATF_REQUIRE_EQ(validateArtifactName("backup_20260502.crate"),      std::string());
  ATF_REQUIRE_EQ(validateArtifactName("v0.6.5.crate"),               std::string());
}

// --- formatExportResponse / formatImportResponse ---

ATF_TEST_CASE_WITHOUT_HEAD(export_response_shape);
ATF_TEST_CASE_BODY(export_response_shape) {
  auto j = formatExportResponse("myapp-1.crate", 12345,
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
  ATF_REQUIRE(j.find("\"file\":\"myapp-1.crate\"") != std::string::npos);
  ATF_REQUIRE(j.find("\"size\":12345")             != std::string::npos);
  ATF_REQUIRE(j.find("\"sha256\":\"abcdef")        != std::string::npos);
  ATF_REQUIRE(j.front() == '{');
  ATF_REQUIRE(j.back()  == '}');
}

ATF_TEST_CASE_WITHOUT_HEAD(import_response_shape);
ATF_TEST_CASE_BODY(import_response_shape) {
  auto j = formatImportResponse("myapp.crate", 0, "deadbeef");
  ATF_REQUIRE(j.find("\"file\":\"myapp.crate\"") != std::string::npos);
  ATF_REQUIRE(j.find("\"size\":0")               != std::string::npos);
  ATF_REQUIRE(j.find("\"sha256\":\"deadbeef\"")  != std::string::npos);
}

// --- sniffArchiveType ---

ATF_TEST_CASE_WITHOUT_HEAD(sniff_xz_signature);
ATF_TEST_CASE_BODY(sniff_xz_signature) {
  std::string xz("\xFD\x37\x7A\x58\x5A\x00 the rest...", 16);
  ATF_REQUIRE_EQ(std::string(sniffArchiveType(xz)), std::string("xz"));
}

ATF_TEST_CASE_WITHOUT_HEAD(sniff_encrypted_signature);
ATF_TEST_CASE_BODY(sniff_encrypted_signature) {
  ATF_REQUIRE_EQ(std::string(sniffArchiveType("Salted__\x01\x02\x03\x04xxxx")),
                 std::string("encrypted"));
}

ATF_TEST_CASE_WITHOUT_HEAD(sniff_unknown_returns_unknown);
ATF_TEST_CASE_BODY(sniff_unknown_returns_unknown) {
  ATF_REQUIRE_EQ(std::string(sniffArchiveType("HelloWorld")), std::string("unknown"));
  ATF_REQUIRE_EQ(std::string(sniffArchiveType("")),           std::string("unknown"));
  // Truncated xz signature — not enough bytes to confirm.
  ATF_REQUIRE_EQ(std::string(sniffArchiveType(std::string("\xFD\x37\x7A", 3))),
                 std::string("unknown"));
}

// --- hexEncode ---

ATF_TEST_CASE_WITHOUT_HEAD(hex_encode_basic_vectors);
ATF_TEST_CASE_BODY(hex_encode_basic_vectors) {
  ATF_REQUIRE_EQ(hexEncode(""),               std::string(""));
  ATF_REQUIRE_EQ(hexEncode(std::string("\x00", 1)), std::string("00"));
  ATF_REQUIRE_EQ(hexEncode(std::string("\xff", 1)), std::string("ff"));
  ATF_REQUIRE_EQ(hexEncode("ABC"),                  std::string("414243"));
  ATF_REQUIRE_EQ(hexEncode(std::string("\xde\xad\xbe\xef", 4)),
                 std::string("deadbeef"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, name_empty_is_rejected);
  ATF_ADD_TEST_CASE(tcs, name_reserved_dot_and_dotdot_rejected);
  ATF_ADD_TEST_CASE(tcs, name_too_long_rejected);
  ATF_ADD_TEST_CASE(tcs, name_path_traversal_rejected);
  ATF_ADD_TEST_CASE(tcs, name_whitespace_rejected);
  ATF_ADD_TEST_CASE(tcs, name_metacharacters_rejected);
  ATF_ADD_TEST_CASE(tcs, name_typical_archives_accepted);
  ATF_ADD_TEST_CASE(tcs, export_response_shape);
  ATF_ADD_TEST_CASE(tcs, import_response_shape);
  ATF_ADD_TEST_CASE(tcs, sniff_xz_signature);
  ATF_ADD_TEST_CASE(tcs, sniff_encrypted_signature);
  ATF_ADD_TEST_CASE(tcs, sniff_unknown_returns_unknown);
  ATF_ADD_TEST_CASE(tcs, hex_encode_basic_vectors);
}
