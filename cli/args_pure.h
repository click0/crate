// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure (platform-independent) helpers used by cli/args.cpp.
// Extracted so unit tests can call them by linking against
// cli/args_pure.cpp instead of duplicating the implementation.

#pragma once

#include "args.h"

namespace ArgsPure {

bool        strEq(const char *s1, const char *s2);
char        isShort(const char *arg);
const char *isLong(const char *arg);
Command     isCommand(const char *arg);

}
