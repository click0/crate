// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "scheduling_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using SchedulingPure::NodeView;
using SchedulingPure::Recommendation;
using SchedulingPure::pickLeastLoaded;
using SchedulingPure::renderRecommendationJson;

static NodeView mk(const std::string &name, const std::string &host,
                   bool reachable, unsigned count) {
  NodeView v;
  v.name = name;
  v.host = host;
  v.reachable = reachable;
  v.containerCount = count;
  return v;
}

// --- pickLeastLoaded ---

ATF_TEST_CASE_WITHOUT_HEAD(empty_input);
ATF_TEST_CASE_BODY(empty_input) {
  auto rec = pickLeastLoaded({});
  ATF_REQUIRE(rec.targetName.empty());
  ATF_REQUIRE_EQ(rec.confidence, 0);
  ATF_REQUIRE(rec.rationale.find("no reachable") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(all_unreachable);
ATF_TEST_CASE_BODY(all_unreachable) {
  std::vector<NodeView> n = {
    mk("alpha", "alpha:9800", false, 1),
    mk("beta",  "beta:9800",  false, 0),
  };
  auto rec = pickLeastLoaded(n);
  ATF_REQUIRE(rec.targetName.empty());
  ATF_REQUIRE_EQ(rec.confidence, 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(picks_lowest_count);
ATF_TEST_CASE_BODY(picks_lowest_count) {
  std::vector<NodeView> n = {
    mk("alpha", "alpha:9800", true, 5),
    mk("beta",  "beta:9800",  true, 2),    // winner
    mk("gamma", "gamma:9800", true, 8),
  };
  auto rec = pickLeastLoaded(n);
  ATF_REQUIRE_EQ(rec.targetName, std::string("beta"));
  ATF_REQUIRE_EQ(rec.targetCount, 2u);
  ATF_REQUIRE_EQ(rec.runnerUpCount, 5u);
  ATF_REQUIRE(rec.confidence > 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(skips_unreachable_in_picking);
ATF_TEST_CASE_BODY(skips_unreachable_in_picking) {
  std::vector<NodeView> n = {
    mk("alpha", "alpha:9800", true,  5),
    mk("beta",  "beta:9800",  false, 0),   // would win but unreachable
    mk("gamma", "gamma:9800", true,  3),   // winner
  };
  auto rec = pickLeastLoaded(n);
  ATF_REQUIRE_EQ(rec.targetName, std::string("gamma"));
  ATF_REQUIRE_EQ(rec.targetCount, 3u);
}

ATF_TEST_CASE_WITHOUT_HEAD(stable_tie_breaker_by_name);
ATF_TEST_CASE_BODY(stable_tie_breaker_by_name) {
  // alpha + beta both have count 3; alpha wins alphabetically.
  std::vector<NodeView> n = {
    mk("beta",  "beta:9800",  true, 3),
    mk("alpha", "alpha:9800", true, 3),
    mk("gamma", "gamma:9800", true, 5),
  };
  auto rec = pickLeastLoaded(n);
  ATF_REQUIRE_EQ(rec.targetName, std::string("alpha"));
}

ATF_TEST_CASE_WITHOUT_HEAD(sole_candidate_full_confidence);
ATF_TEST_CASE_BODY(sole_candidate_full_confidence) {
  std::vector<NodeView> n = {
    mk("alpha", "alpha:9800", true, 7),
  };
  auto rec = pickLeastLoaded(n);
  ATF_REQUIRE_EQ(rec.targetName, std::string("alpha"));
  ATF_REQUIRE_EQ(rec.confidence, 100);
}

ATF_TEST_CASE_WITHOUT_HEAD(confidence_scales_with_spread);
ATF_TEST_CASE_BODY(confidence_scales_with_spread) {
  // Big spread (1 vs 100) -> high confidence.
  std::vector<NodeView> big = {
    mk("alpha", "alpha:9800", true, 1),
    mk("beta",  "beta:9800",  true, 100),
  };
  auto bigRec = pickLeastLoaded(big);
  ATF_REQUIRE(bigRec.confidence >= 90);

  // Tight spread (10 vs 11) -> low confidence.
  std::vector<NodeView> tight = {
    mk("alpha", "alpha:9800", true, 10),
    mk("beta",  "beta:9800",  true, 11),
  };
  auto tightRec = pickLeastLoaded(tight);
  ATF_REQUIRE(tightRec.confidence < 20);
}

// --- anti-flap ---

ATF_TEST_CASE_WITHOUT_HEAD(anti_flap_keeps_current_within_tolerance);
ATF_TEST_CASE_BODY(anti_flap_keeps_current_within_tolerance) {
  // Current host count=3; least-loaded count=3 too — within 10% (or
  // exact). Should keep current.
  std::vector<NodeView> n = {
    mk("alpha", "alpha:9800", true, 3),  // least-loaded by name tie
    mk("beta",  "beta:9800",  true, 3),  // current; equal -> within tolerance
  };
  auto rec = pickLeastLoaded(n, "beta");
  ATF_REQUIRE_EQ(rec.targetName, std::string("beta"));
  ATF_REQUIRE_EQ(rec.confidence, 100);
  ATF_REQUIRE(rec.rationale.find("keep on") != std::string::npos);
  ATF_REQUIRE(rec.rationale.find("within") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(anti_flap_migrates_when_current_too_loaded);
ATF_TEST_CASE_BODY(anti_flap_migrates_when_current_too_loaded) {
  // Current count=20; least-loaded count=10 -> 20 > 10 + 10% (=11).
  // Migrate.
  std::vector<NodeView> n = {
    mk("alpha", "alpha:9800", true, 10),
    mk("beta",  "beta:9800",  true, 20),
  };
  auto rec = pickLeastLoaded(n, "beta");
  ATF_REQUIRE_EQ(rec.targetName, std::string("alpha"));
  ATF_REQUIRE(rec.rationale.find("place on") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(anti_flap_unknown_hint_falls_through);
ATF_TEST_CASE_BODY(anti_flap_unknown_hint_falls_through) {
  // Hint references a node not in the cluster — fall through to
  // straight least-loaded pick, no error.
  std::vector<NodeView> n = {
    mk("alpha", "alpha:9800", true, 2),
    mk("beta",  "beta:9800",  true, 5),
  };
  auto rec = pickLeastLoaded(n, "nonexistent");
  ATF_REQUIRE_EQ(rec.targetName, std::string("alpha"));
}

ATF_TEST_CASE_WITHOUT_HEAD(anti_flap_hint_to_unreachable_falls_through);
ATF_TEST_CASE_BODY(anti_flap_hint_to_unreachable_falls_through) {
  // Hint references a node that's currently unreachable — the
  // anti-flap rule shouldn't apply (the container can't stay there
  // anyway). Fall through to least-loaded among reachable.
  std::vector<NodeView> n = {
    mk("alpha", "alpha:9800", true,  10),
    mk("beta",  "beta:9800",  false, 3),
    mk("gamma", "gamma:9800", true,  5),
  };
  auto rec = pickLeastLoaded(n, "beta");
  ATF_REQUIRE_EQ(rec.targetName, std::string("gamma"));
}

// --- renderRecommendationJson ---

ATF_TEST_CASE_WITHOUT_HEAD(json_no_candidate_emits_null_target);
ATF_TEST_CASE_BODY(json_no_candidate_emits_null_target) {
  auto rec = pickLeastLoaded({});
  auto json = renderRecommendationJson(rec);
  ATF_REQUIRE(json.find("\"target\":null") != std::string::npos);
  ATF_REQUIRE(json.find("\"rationale\":") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(json_full_recommendation_shape);
ATF_TEST_CASE_BODY(json_full_recommendation_shape) {
  std::vector<NodeView> n = {
    mk("alpha", "alpha.example.com:9800", true, 1),
    mk("beta",  "beta.example.com:9800",  true, 5),
  };
  auto rec = pickLeastLoaded(n);
  auto json = renderRecommendationJson(rec);
  ATF_REQUIRE(json.find("\"target\":\"alpha\"") != std::string::npos);
  ATF_REQUIRE(json.find("\"host\":\"alpha.example.com:9800\"") != std::string::npos);
  ATF_REQUIRE(json.find("\"container_count\":1") != std::string::npos);
  ATF_REQUIRE(json.find("\"runner_up_count\":5") != std::string::npos);
  ATF_REQUIRE(json.find("\"confidence\":") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(json_quotes_special_chars);
ATF_TEST_CASE_BODY(json_quotes_special_chars) {
  // Defensive: if a node name somehow had a quote, JSON should
  // escape it. (Names are validated upstream so this is hypothetical.)
  Recommendation rec;
  rec.targetName = "node\"with\"quotes";
  rec.targetHost = "h:1";
  rec.targetCount = 0;
  rec.confidence = 100;
  rec.rationale = "ok";
  auto json = renderRecommendationJson(rec);
  ATF_REQUIRE(json.find("\\\"with\\\"") != std::string::npos);
}

// --- 0.8.43: CLI helper plumbing ---

ATF_TEST_CASE_WITHOUT_HEAD(url_no_hint);
ATF_TEST_CASE_BODY(url_no_hint) {
  ATF_REQUIRE_EQ(SchedulingPure::buildLeastLoadedUrl("http://hub:9810", ""),
                 std::string("http://hub:9810/api/v1/scheduling/least-loaded"));
}

ATF_TEST_CASE_WITHOUT_HEAD(url_with_hint);
ATF_TEST_CASE_BODY(url_with_hint) {
  ATF_REQUIRE_EQ(SchedulingPure::buildLeastLoadedUrl("http://hub:9810", "alpha"),
                 std::string("http://hub:9810/api/v1/scheduling/least-loaded?current=alpha"));
}

ATF_TEST_CASE_WITHOUT_HEAD(url_strips_trailing_slash);
ATF_TEST_CASE_BODY(url_strips_trailing_slash) {
  ATF_REQUIRE_EQ(SchedulingPure::buildLeastLoadedUrl("http://hub:9810/", "foo"),
                 std::string("http://hub:9810/api/v1/scheduling/least-loaded?current=foo"));
}

ATF_TEST_CASE_WITHOUT_HEAD(url_empty_base_returns_path_only);
ATF_TEST_CASE_BODY(url_empty_base_returns_path_only) {
  // Used by the CLI helper when cpp-httplib's Client already
  // owns the host+port; passing the whole URL back through
  // Get() would double up.
  ATF_REQUIRE_EQ(SchedulingPure::buildLeastLoadedUrl("", "alpha"),
                 std::string("/api/v1/scheduling/least-loaded?current=alpha"));
  ATF_REQUIRE_EQ(SchedulingPure::buildLeastLoadedUrl("", ""),
                 std::string("/api/v1/scheduling/least-loaded"));
}

ATF_TEST_CASE_WITHOUT_HEAD(url_encodes_special_chars);
ATF_TEST_CASE_BODY(url_encodes_special_chars) {
  // Defensive — jail names go through validators upstream that
  // reject these characters, but defence-in-depth.
  auto out = SchedulingPure::buildLeastLoadedUrl("http://h", "a b");
  ATF_REQUIRE(out.find("?current=a%20b") != std::string::npos);
  out = SchedulingPure::buildLeastLoadedUrl("http://h", "a&b");
  ATF_REQUIRE(out.find("%26") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_target_quoted_string);
ATF_TEST_CASE_BODY(extract_target_quoted_string) {
  std::string body =
    "{\"status\":\"ok\",\"data\":{\"target\":\"alpha\","
    "\"host\":\"alpha:9800\",\"container_count\":3}}";
  ATF_REQUIRE_EQ(SchedulingPure::extractTargetField(body), std::string("alpha"));
  ATF_REQUIRE_EQ(SchedulingPure::extractHostField(body), std::string("alpha:9800"));
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_target_null_returns_empty);
ATF_TEST_CASE_BODY(extract_target_null_returns_empty) {
  std::string body =
    "{\"status\":\"ok\",\"data\":{\"target\":null,"
    "\"rationale\":\"no reachable nodes\"}}";
  ATF_REQUIRE_EQ(SchedulingPure::extractTargetField(body), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_target_tolerates_whitespace);
ATF_TEST_CASE_BODY(extract_target_tolerates_whitespace) {
  // jq-printed bodies have whitespace after the colon; our own
  // renderRecommendationJson doesn't. Match either.
  std::string body = "{ \"target\" : \"beta\" , \"host\" : \"beta:9800\" }";
  ATF_REQUIRE_EQ(SchedulingPure::extractTargetField(body), std::string("beta"));
  ATF_REQUIRE_EQ(SchedulingPure::extractHostField(body), std::string("beta:9800"));
}

ATF_TEST_CASE_WITHOUT_HEAD(extract_target_missing_returns_empty);
ATF_TEST_CASE_BODY(extract_target_missing_returns_empty) {
  std::string body = "{\"status\":\"error\",\"error\":\"oops\"}";
  ATF_REQUIRE_EQ(SchedulingPure::extractTargetField(body), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(migrate_argv_shape);
ATF_TEST_CASE_BODY(migrate_argv_shape) {
  auto argv = SchedulingPure::buildMigrateArgv(
    "/usr/local/bin/crate", "myjail",
    "alpha:9800", "beta:9800",
    "/etc/.src-token", "/etc/.dst-token");
  ATF_REQUIRE_EQ(argv.size(), (size_t)11);
  ATF_REQUIRE_EQ(argv[0], std::string("/usr/local/bin/crate"));
  ATF_REQUIRE_EQ(argv[1], std::string("migrate"));
  ATF_REQUIRE_EQ(argv[2], std::string("myjail"));
  ATF_REQUIRE_EQ(argv[3], std::string("--from"));
  ATF_REQUIRE_EQ(argv[4], std::string("alpha:9800"));
  ATF_REQUIRE_EQ(argv[5], std::string("--to"));
  ATF_REQUIRE_EQ(argv[6], std::string("beta:9800"));
  ATF_REQUIRE_EQ(argv[7], std::string("--from-token-file"));
  ATF_REQUIRE_EQ(argv[8], std::string("/etc/.src-token"));
  ATF_REQUIRE_EQ(argv[9], std::string("--to-token-file"));
  ATF_REQUIRE_EQ(argv[10], std::string("/etc/.dst-token"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, empty_input);
  ATF_ADD_TEST_CASE(tcs, all_unreachable);
  ATF_ADD_TEST_CASE(tcs, picks_lowest_count);
  ATF_ADD_TEST_CASE(tcs, skips_unreachable_in_picking);
  ATF_ADD_TEST_CASE(tcs, stable_tie_breaker_by_name);
  ATF_ADD_TEST_CASE(tcs, sole_candidate_full_confidence);
  ATF_ADD_TEST_CASE(tcs, confidence_scales_with_spread);
  ATF_ADD_TEST_CASE(tcs, anti_flap_keeps_current_within_tolerance);
  ATF_ADD_TEST_CASE(tcs, anti_flap_migrates_when_current_too_loaded);
  ATF_ADD_TEST_CASE(tcs, anti_flap_unknown_hint_falls_through);
  ATF_ADD_TEST_CASE(tcs, anti_flap_hint_to_unreachable_falls_through);
  ATF_ADD_TEST_CASE(tcs, json_no_candidate_emits_null_target);
  ATF_ADD_TEST_CASE(tcs, json_full_recommendation_shape);
  ATF_ADD_TEST_CASE(tcs, json_quotes_special_chars);
  ATF_ADD_TEST_CASE(tcs, url_no_hint);
  ATF_ADD_TEST_CASE(tcs, url_with_hint);
  ATF_ADD_TEST_CASE(tcs, url_strips_trailing_slash);
  ATF_ADD_TEST_CASE(tcs, url_empty_base_returns_path_only);
  ATF_ADD_TEST_CASE(tcs, url_encodes_special_chars);
  ATF_ADD_TEST_CASE(tcs, extract_target_quoted_string);
  ATF_ADD_TEST_CASE(tcs, extract_target_null_returns_empty);
  ATF_ADD_TEST_CASE(tcs, extract_target_tolerates_whitespace);
  ATF_ADD_TEST_CASE(tcs, extract_target_missing_returns_empty);
  ATF_ADD_TEST_CASE(tcs, migrate_argv_shape);
}
