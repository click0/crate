// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Runtime helper for default-route interface detection (0.8.6).
// Pure parsing in lib/net_detect_pure.h; this side does the
// fork+exec of `route -4 get default` and caches the result.
//

#include <string>

namespace NetDetect {

// Return the interface name that hosts the IPv4 default route.
// Empty string on failure (no route, route(8) not found, parser
// rejected the output).
//
// Cached: the first call invokes route(8); subsequent calls return
// the cached value. crated runs as a long-lived daemon so the
// default route shouldn't change under its feet often. If it does,
// `clearCache()` forces a re-detect on next call.
std::string defaultIfaceCached();

// Force a re-detect on the next call. Used by `crate doctor` and
// future hooks that want a fresh read.
void clearCache();

} // namespace NetDetect
