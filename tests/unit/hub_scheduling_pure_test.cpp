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
}
