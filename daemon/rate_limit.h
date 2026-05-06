// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Runtime side of the crated rate limiter (0.7.15).
//
// Thread-safe wrapper over RateLimitPure::check using a global
// std::mutex + std::unordered_map<std::string, Bucket>. Designed
// to be called from any handler that wants to throttle a given
// {clientId, endpoint} pair.
//
// On a hot path the mutex contention is fine: this is a daemon
// processing tens of req/sec, not millions. If that ever changes
// we'd reach for sharded buckets or atomic-only paths.
//

#include <string>

namespace RateLimit {

// Stable cap constants — match the pre-existing routes.cpp values
// so day-1 behaviour is identical to before. Operators tune by
// editing this file (real config-driven limits is a future item).
inline constexpr int kRead     = 100;  // per second per client+endpoint
inline constexpr int kMutating = 10;

// True if the request should be allowed. Allocates a bucket the
// first time `key` is seen. The same key can mix high- and low-cap
// callers (bucket state is shared), but in practice each call site
// uses a unique key prefix per cap class.
bool check(const std::string &key, int maxPerSecond);

// Forget all bucket state — used by tests.
void reset();

} // namespace RateLimit
