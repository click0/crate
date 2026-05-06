// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "rate_limit.h"
#include "rate_limit_pure.h"

#include <ctime>
#include <mutex>
#include <unordered_map>

namespace RateLimit {

namespace {

std::mutex                                                   g_mu;
std::unordered_map<std::string, RateLimitPure::Bucket>       g_buckets;

} // anon

bool check(const std::string &key, int maxPerSecond) {
  std::lock_guard<std::mutex> lock(g_mu);
  auto &b = g_buckets[key];
  auto d = RateLimitPure::check(b, ::time(nullptr), maxPerSecond);
  b = d.newState;
  return d.allowed;
}

void reset() {
  std::lock_guard<std::mutex> lock(g_mu);
  g_buckets.clear();
}

} // namespace RateLimit
