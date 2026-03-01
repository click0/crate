// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

void createJailsDirectoryIfNeeded(const char *subdir = ""); // subdir is assumed to include the leading slash when non-empty
void createCacheDirectoryIfNeeded();
