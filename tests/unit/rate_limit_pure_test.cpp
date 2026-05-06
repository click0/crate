// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "rate_limit_pure.h"

#include <atf-c++.hpp>

using RateLimitPure::Bucket;
using RateLimitPure::Decision;
using RateLimitPure::check;
using RateLimitPure::retryAfterSeconds;

ATF_TEST_CASE_WITHOUT_HEAD(fresh_bucket_is_allowed);
ATF_TEST_CASE_BODY(fresh_bucket_is_allowed) {
  // The empty-bucket sentinel is {0, 0}. Any first request lands in
  // a "different second" branch and is allowed.
  auto d = check(Bucket{}, /*now=*/1700000000, /*max=*/10);
  ATF_REQUIRE(d.allowed);
  ATF_REQUIRE_EQ(d.newState.counter, 1);
  ATF_REQUIRE_EQ(d.newState.second,  1700000000L);
}

ATF_TEST_CASE_WITHOUT_HEAD(below_cap_increments);
ATF_TEST_CASE_BODY(below_cap_increments) {
  Bucket b{5, 1700000000};
  auto d = check(b, 1700000000, /*max=*/10);
  ATF_REQUIRE(d.allowed);
  ATF_REQUIRE_EQ(d.newState.counter, 6);
  ATF_REQUIRE_EQ(d.newState.second,  1700000000L);
}

ATF_TEST_CASE_WITHOUT_HEAD(at_cap_last_request_allowed);
ATF_TEST_CASE_BODY(at_cap_last_request_allowed) {
  // counter == max-1 -> next request brings it to max and is allowed.
  Bucket b{9, 1700000000};
  auto d = check(b, 1700000000, /*max=*/10);
  ATF_REQUIRE(d.allowed);
  ATF_REQUIRE_EQ(d.newState.counter, 10);
}

ATF_TEST_CASE_WITHOUT_HEAD(above_cap_denied);
ATF_TEST_CASE_BODY(above_cap_denied) {
  // counter == max -> request denied, counter stays put.
  Bucket b{10, 1700000000};
  auto d = check(b, 1700000000, /*max=*/10);
  ATF_REQUIRE(!d.allowed);
  ATF_REQUIRE_EQ(d.newState.counter, 10);  // does NOT drift past max
  ATF_REQUIRE_EQ(d.newState.second,  1700000000L);
}

ATF_TEST_CASE_WITHOUT_HEAD(many_denies_dont_drift_counter);
ATF_TEST_CASE_BODY(many_denies_dont_drift_counter) {
  // Property: a flood of post-cap requests never pushes counter
  // beyond max. Important for any future telemetry that wants to
  // read counter as "requests this second".
  Bucket b{10, 1700000000};
  for (int i = 0; i < 1000; i++) {
    auto d = check(b, 1700000000, 10);
    ATF_REQUIRE(!d.allowed);
    ATF_REQUIRE_EQ(d.newState.counter, 10);
    b = d.newState;
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(second_rollover_resets_counter);
ATF_TEST_CASE_BODY(second_rollover_resets_counter) {
  // After the wall second ticks, the counter resets to 1 (this
  // request is the first of the new second, not the zeroth).
  Bucket b{10, 1700000000};
  auto d = check(b, 1700000001, 10);
  ATF_REQUIRE(d.allowed);
  ATF_REQUIRE_EQ(d.newState.counter, 1);
  ATF_REQUIRE_EQ(d.newState.second,  1700000001L);
}

ATF_TEST_CASE_WITHOUT_HEAD(non_monotonic_clock_still_resets);
ATF_TEST_CASE_BODY(non_monotonic_clock_still_resets) {
  // Operator runs ntpd / steps the clock backward — bucket second
  // is "in the future" relative to now. We treat that as a different
  // second and reset, same as the forward case. (We use wall-clock
  // CLOCK_REALTIME on purpose so log lines line up; CLOCK_MONOTONIC
  // wouldn't help here because we'd still want resets on adjustments.)
  Bucket b{10, 1700000005};
  auto d = check(b, 1700000000, 10);  // now is BEFORE bucket.second
  ATF_REQUIRE(d.allowed);
  ATF_REQUIRE_EQ(d.newState.counter, 1);
  ATF_REQUIRE_EQ(d.newState.second,  1700000000L);
}

ATF_TEST_CASE_WITHOUT_HEAD(zero_max_treated_as_disabled);
ATF_TEST_CASE_BODY(zero_max_treated_as_disabled) {
  // A typo flipping the constant to 0 shouldn't permanently brick
  // the daemon. We treat <=0 as "disabled" -> always allow.
  Bucket b{};
  auto d = check(b, 1700000000, 0);
  ATF_REQUIRE(d.allowed);
  // And again with negative.
  d = check(b, 1700000000, -5);
  ATF_REQUIRE(d.allowed);
}

ATF_TEST_CASE_WITHOUT_HEAD(retry_after_is_one_second);
ATF_TEST_CASE_BODY(retry_after_is_one_second) {
  // The bucket flips on the next wall second; longer Retry-After
  // would mislead well-behaved clients into backing off too hard.
  ATF_REQUIRE_EQ(retryAfterSeconds(), 1);
}

ATF_TEST_CASE_WITHOUT_HEAD(allows_exactly_max_requests_per_second);
ATF_TEST_CASE_BODY(allows_exactly_max_requests_per_second) {
  // Property: with a fresh bucket and a single second, exactly `max`
  // requests are allowed before denials kick in.
  Bucket b{};
  long now = 1700000000;
  int max  = 7;
  int allowed = 0, denied = 0;
  for (int i = 0; i < max + 5; i++) {
    auto d = check(b, now, max);
    if (d.allowed) allowed++;
    else           denied++;
    b = d.newState;
  }
  ATF_REQUIRE_EQ(allowed, max);
  ATF_REQUIRE_EQ(denied,  5);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, fresh_bucket_is_allowed);
  ATF_ADD_TEST_CASE(tcs, below_cap_increments);
  ATF_ADD_TEST_CASE(tcs, at_cap_last_request_allowed);
  ATF_ADD_TEST_CASE(tcs, above_cap_denied);
  ATF_ADD_TEST_CASE(tcs, many_denies_dont_drift_counter);
  ATF_ADD_TEST_CASE(tcs, second_rollover_resets_counter);
  ATF_ADD_TEST_CASE(tcs, non_monotonic_clock_still_resets);
  ATF_ADD_TEST_CASE(tcs, zero_max_treated_as_disabled);
  ATF_ADD_TEST_CASE(tcs, retry_after_is_one_second);
  ATF_ADD_TEST_CASE(tcs, allows_exactly_max_requests_per_second);
}
