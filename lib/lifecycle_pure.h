// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers extracted from lib/lifecycle.cpp for unit testing.

#pragma once

#include <cstdint>
#include <string>

namespace LifecyclePure {

std::string humanBytes(uint64_t bytes);

// 1.1.44: `netstat -I <iface> -b -n --libxo json` →
// {"statistics":{"interface":[{"name":"epair0a",...,"received-bytes":N,
// ...,"sent-bytes":N,...}, ...]}}. Finds the object whose "name" is
// `iface` and returns its received/sent byte counters. False when the
// text is not that shape or the interface is absent. Deliberately a
// scanner, not a JSON parser: the two fields are flat numbers in a
// well-known document.
bool parseNetstatIfaceBytesJson(const std::string &json, const std::string &iface,
                                uint64_t &ibytes, uint64_t &obytes);

}
