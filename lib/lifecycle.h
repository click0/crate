// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Container lifecycle commands: stats, logs, stop, restart.

#pragma once

class Args;

bool statsCrate(const Args &args);
bool logsCrate(const Args &args);
bool stopCrate(const Args &args);
bool restartCrate(const Args &args);
