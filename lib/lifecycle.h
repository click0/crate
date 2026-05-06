// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Container lifecycle commands: stats, logs, stop, restart.
//
// These declarations are NOT included directly anywhere in the
// codebase — `lib/commands.h` redeclares the same symbols and is
// the single header CLI dispatch + tests pull in. This header is
// kept as the canonical source-of-truth for the lifecycle.cpp
// implementation file (i.e. lifecycle.cpp #include's it for type
// alignment) and as a future hook for callers that want only the
// lifecycle subset without dragging in the full commands.h.
//
// If you grep for `#include "lifecycle.h"` and find only
// lib/lifecycle.cpp itself: that is intentional, not dead code.

#pragma once

class Args;

bool statsCrate(const Args &args);
bool logsCrate(const Args &args);
bool stopCrate(const Args &args);
bool restartCrate(const Args &args);
