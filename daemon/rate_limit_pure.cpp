// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "rate_limit_pure.h"

namespace RateLimitPure {

Decision check(Bucket bucket, long now, int maxPerSecond) {
  Decision d;
  if (maxPerSecond <= 0) {
    // Pathological / disabled limit. Treat as allow with a fresh
    // bucket so callers who flip the constant to 0 don't accumulate
    // stale state.
    d.newState = {0, now};
    d.allowed  = true;
    return d;
  }

  if (bucket.second != now) {
    // First request of a new second (or fresh bucket).
    d.newState = {1, now};
    d.allowed  = true;
    return d;
  }

  // Same second.
  if (bucket.counter < maxPerSecond) {
    d.newState = {bucket.counter + 1, now};
    d.allowed  = true;
    return d;
  }

  // Cap reached. Don't increment past the cap — over-counting would
  // be harmless (still denies) but pollutes any future telemetry that
  // wants to read the counter as "requests this second".
  d.newState = bucket;
  d.allowed  = false;
  return d;
}

} // namespace RateLimitPure
