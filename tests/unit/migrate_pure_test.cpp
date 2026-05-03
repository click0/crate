// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "migrate_pure.h"

#include <atf-c++.hpp>

#include <string>

using MigratePure::Request;
using MigratePure::Step;
using MigratePure::StepKind;
using MigratePure::buildExportStep;
using MigratePure::buildRemainingSteps;
using MigratePure::describeStep;
using MigratePure::normalizeBaseUrl;
using MigratePure::redactToken;
using MigratePure::validateBearerToken;
using MigratePure::validateContainerName;
using MigratePure::validateEndpoint;

// --- validateEndpoint ---

ATF_TEST_CASE_WITHOUT_HEAD(endpoint_typical_accepted);
ATF_TEST_CASE_BODY(endpoint_typical_accepted) {
  ATF_REQUIRE_EQ(validateEndpoint("alpha.example.com:9800"),         std::string());
  ATF_REQUIRE_EQ(validateEndpoint("10.0.0.5:9800"),                  std::string());
  ATF_REQUIRE_EQ(validateEndpoint("[::1]:9800"),                     std::string());
  ATF_REQUIRE_EQ(validateEndpoint("[2001:db8::1]:9800"),             std::string());
  ATF_REQUIRE_EQ(validateEndpoint("https://alpha.example.com:9800"), std::string());
  ATF_REQUIRE_EQ(validateEndpoint("http://10.0.0.5:9800"),           std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(endpoint_invalid_rejected);
ATF_TEST_CASE_BODY(endpoint_invalid_rejected) {
  ATF_REQUIRE(!validateEndpoint("").empty());
  ATF_REQUIRE(!validateEndpoint("alpha").empty());            // no port
  ATF_REQUIRE(!validateEndpoint("alpha:99999").empty());      // port out of range
  ATF_REQUIRE(!validateEndpoint("256.0.0.1:80").empty());     // bad octet — RFC violation
  ATF_REQUIRE(!validateEndpoint("[::1]").empty());            // missing :port
  ATF_REQUIRE(!validateEndpoint("[zzz::1]:80").empty());      // bad v6
  ATF_REQUIRE(!validateEndpoint("under_score:80").empty());   // illegal hostname char
  ATF_REQUIRE(!validateEndpoint("https://").empty());         // bare scheme
}

// --- validateBearerToken ---

ATF_TEST_CASE_WITHOUT_HEAD(token_typical_accepted);
ATF_TEST_CASE_BODY(token_typical_accepted) {
  // Real-world admin tokens look like base64 sha256 hashes — accept those.
  ATF_REQUIRE_EQ(validateBearerToken("abcdef0123456789abcdef0123456789ABCDEF"),
                 std::string());
  ATF_REQUIRE_EQ(validateBearerToken("a"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(token_invalid_rejected);
ATF_TEST_CASE_BODY(token_invalid_rejected) {
  ATF_REQUIRE(!validateBearerToken("").empty());
  ATF_REQUIRE(!validateBearerToken("has whitespace").empty());
  ATF_REQUIRE(!validateBearerToken("has\ttab").empty());
  ATF_REQUIRE(!validateBearerToken("has\nnewline").empty());
  ATF_REQUIRE(!validateBearerToken(std::string("ctl\x01char", 8)).empty());
  ATF_REQUIRE(!validateBearerToken(std::string(513, 'a')).empty());
}

// --- validateContainerName ---

ATF_TEST_CASE_WITHOUT_HEAD(name_typical_accepted);
ATF_TEST_CASE_BODY(name_typical_accepted) {
  ATF_REQUIRE_EQ(validateContainerName("myjail"),         std::string());
  ATF_REQUIRE_EQ(validateContainerName("postgres-prod"),  std::string());
  ATF_REQUIRE_EQ(validateContainerName("a.b.c"),          std::string());
  ATF_REQUIRE_EQ(validateContainerName("v0.6.13"),        std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(name_invalid_rejected);
ATF_TEST_CASE_BODY(name_invalid_rejected) {
  ATF_REQUIRE(!validateContainerName("").empty());
  ATF_REQUIRE(!validateContainerName(".").empty());
  ATF_REQUIRE(!validateContainerName("..").empty());
  ATF_REQUIRE(!validateContainerName(std::string(65, 'a')).empty());
  ATF_REQUIRE(!validateContainerName("foo/bar").empty());
  ATF_REQUIRE(!validateContainerName("foo bar").empty());
  ATF_REQUIRE(!validateContainerName("foo;rm").empty());
}

// --- normalizeBaseUrl ---

ATF_TEST_CASE_WITHOUT_HEAD(normalize_adds_https_when_missing);
ATF_TEST_CASE_BODY(normalize_adds_https_when_missing) {
  ATF_REQUIRE_EQ(normalizeBaseUrl("alpha:9800"),
                 std::string("https://alpha:9800"));
  ATF_REQUIRE_EQ(normalizeBaseUrl("10.0.0.5:9800"),
                 std::string("https://10.0.0.5:9800"));
}

ATF_TEST_CASE_WITHOUT_HEAD(normalize_preserves_existing_scheme);
ATF_TEST_CASE_BODY(normalize_preserves_existing_scheme) {
  ATF_REQUIRE_EQ(normalizeBaseUrl("https://alpha:9800"),
                 std::string("https://alpha:9800"));
  ATF_REQUIRE_EQ(normalizeBaseUrl("http://10.0.0.5:9800"),
                 std::string("http://10.0.0.5:9800"));
}

// --- buildExportStep ---

ATF_TEST_CASE_WITHOUT_HEAD(build_export_step_shape);
ATF_TEST_CASE_BODY(build_export_step_shape) {
  Request r;
  r.name = "myjail";
  r.fromEndpoint = "alpha:9800";
  r.fromToken    = "TOK-ALPHA";
  auto s = buildExportStep(r);
  ATF_REQUIRE(s.kind == StepKind::Export);
  ATF_REQUIRE_EQ(s.method, std::string("POST"));
  ATF_REQUIRE_EQ(s.url, std::string("https://alpha:9800/api/v1/containers/myjail/export"));
  ATF_REQUIRE_EQ(s.token, std::string("TOK-ALPHA"));
}

// --- buildRemainingSteps ---

ATF_TEST_CASE_WITHOUT_HEAD(build_remaining_steps_full_chain);
ATF_TEST_CASE_BODY(build_remaining_steps_full_chain) {
  Request r;
  r.name = "myjail";
  r.fromEndpoint = "https://alpha:9800";
  r.fromToken    = "TOK-A";
  r.toEndpoint   = "beta:9800";
  r.toToken      = "TOK-B";
  r.workDir      = "/tmp/migrate-1";
  r.artifactFile = "myjail-1730000000.crate";

  auto steps = buildRemainingSteps(r);
  ATF_REQUIRE_EQ(steps.size(), (size_t)4);

  ATF_REQUIRE(steps[0].kind == StepKind::Download);
  ATF_REQUIRE_EQ(steps[0].method, std::string("GET"));
  ATF_REQUIRE_EQ(steps[0].url,
    std::string("https://alpha:9800/api/v1/exports/myjail-1730000000.crate"));
  ATF_REQUIRE_EQ(steps[0].filePath,
    std::string("/tmp/migrate-1/myjail-1730000000.crate"));

  ATF_REQUIRE(steps[1].kind == StepKind::Upload);
  ATF_REQUIRE_EQ(steps[1].method, std::string("POST"));
  ATF_REQUIRE_EQ(steps[1].url,
    std::string("https://beta:9800/api/v1/imports/myjail"));
  ATF_REQUIRE_EQ(steps[1].token, std::string("TOK-B"));

  ATF_REQUIRE(steps[2].kind == StepKind::StartTo);
  ATF_REQUIRE_EQ(steps[2].url,
    std::string("https://beta:9800/api/v1/containers/myjail/start"));

  ATF_REQUIRE(steps[3].kind == StepKind::StopFrom);
  ATF_REQUIRE_EQ(steps[3].url,
    std::string("https://alpha:9800/api/v1/containers/myjail/stop"));
}

ATF_TEST_CASE_WITHOUT_HEAD(plan_stop_source_only_runs_after_start_dest);
ATF_TEST_CASE_BODY(plan_stop_source_only_runs_after_start_dest) {
  // Order invariant: StopFrom is the LAST step; StartTo is the
  // step just before it. The runtime must abort the plan before
  // StopFrom on any earlier failure, so that the source container
  // keeps running if anything went wrong.
  Request r;
  r.name = "j"; r.fromEndpoint = "a:9800"; r.toEndpoint = "b:9800";
  r.fromToken = "x"; r.toToken = "y";
  r.workDir = "/tmp"; r.artifactFile = "j.crate";
  auto steps = buildRemainingSteps(r);
  ATF_REQUIRE(steps.back().kind == StepKind::StopFrom);
  ATF_REQUIRE(steps.size() >= 2);
  ATF_REQUIRE(steps[steps.size() - 2].kind == StepKind::StartTo);
}

// --- describeStep / redactToken ---

ATF_TEST_CASE_WITHOUT_HEAD(describe_includes_method_and_url);
ATF_TEST_CASE_BODY(describe_includes_method_and_url) {
  Step s;
  s.kind = StepKind::Export;
  s.method = "POST";
  s.url = "https://alpha:9800/api/v1/containers/myjail/export";
  s.token = "SECRET-TOKEN";
  auto desc = describeStep(s);
  ATF_REQUIRE(desc.find("POST")          != std::string::npos);
  ATF_REQUIRE(desc.find("alpha:9800")    != std::string::npos);
  ATF_REQUIRE(desc.find("export")        != std::string::npos);
  // Token must NEVER leak into log description.
  ATF_REQUIRE(desc.find("SECRET-TOKEN")  == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(redact_token_does_not_leak_value);
ATF_TEST_CASE_BODY(redact_token_does_not_leak_value) {
  std::string tok = "actual-secret-value";
  auto r = redactToken(tok);
  ATF_REQUIRE(r.find(tok)        == std::string::npos);
  ATF_REQUIRE(r.find("redacted") != std::string::npos);
  // Length is fine to expose — it's a sanity hint, not the secret.
  ATF_REQUIRE(r.find(std::to_string(tok.size())) != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, endpoint_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, endpoint_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, token_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, token_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, name_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, name_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, normalize_adds_https_when_missing);
  ATF_ADD_TEST_CASE(tcs, normalize_preserves_existing_scheme);
  ATF_ADD_TEST_CASE(tcs, build_export_step_shape);
  ATF_ADD_TEST_CASE(tcs, build_remaining_steps_full_chain);
  ATF_ADD_TEST_CASE(tcs, plan_stop_source_only_runs_after_start_dest);
  ATF_ADD_TEST_CASE(tcs, describe_includes_method_and_url);
  ATF_ADD_TEST_CASE(tcs, redact_token_does_not_leak_value);
}
