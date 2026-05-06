// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for the rate-limiter (0.7.15).
//
// crated already had a per-second token-bucket inside daemon/routes.cpp
// (the main HTTP API) but the new control-socket plane (0.7.10/0.7.11)
// shipped without one — a buggy GUI/tray polling the socket in a tight
// loop could spin crated up. This module factors the bucketing logic
// into a pure function reusable from both planes (control_socket
// activates it now; routes.cpp can refactor onto it later without
// behaviour change).
//
// Algorithm: per-second counter buckets keyed by (clientId, endpoint).
// A request is allowed iff the counter for the current wall second is
// at most maxPerSecond. Coarse but cheap: O(1) per check, no floating-
// point, no sliding-window state. Same semantics as the existing
// routes.cpp limiter so operators don't have to learn two models.
//
// All wall-clock + threading lives in daemon/rate_limit.{h,cpp}.
//

#include <cstdint>

namespace RateLimitPure {

// Per-key bucket state. (counter == 0 && second == 0) is the
// uninitialised marker — any new key starts there.
struct Bucket {
  int  counter = 0;
  long second  = 0;   // unix epoch seconds
};

struct Decision {
  Bucket newState;
  bool   allowed = false;
};

// Pure check: given the previous bucket state, the current wall
// second, and the per-second cap, return the new state and whether
// this request is allowed.
//
// Rules:
//   - Different second from the bucket's: reset to {1, now}, allow.
//   - Same second, counter < max: increment, allow.
//   - Same second, counter == max: do NOT increment; deny.
//
// The non-incrementing deny path matters for tests: a flood of
// rejected requests must not push the counter into a "permanently
// denying for the rest of the second" state — the counter caps
// at max, never drifts above.
Decision check(Bucket bucket, long now, int maxPerSecond);

// Stable HTTP-429 retry-after hint. We always advise "1" because the
// bucket flips at the next wall second; a longer hint would mislead
// well-behaved clients into backing off too hard.
inline constexpr int retryAfterSeconds() { return 1; }

} // namespace RateLimitPure
