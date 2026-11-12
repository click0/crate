// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

#include <string>

// subdir is assumed to include the leading slash when non-empty.
// 1.1.73: also /var/run/crate/0; returns a note ("" normally) when
// /var/run/crate has to stay 0700 for pre-1.1.73 jail trees.
std::string createJailsDirectoryIfNeeded(const char *subdir = "");
void createCacheDirectoryIfNeeded();
