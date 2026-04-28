// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers extracted from lib/scripts.cpp for unit testing.

#pragma once

#include <string>

namespace ScriptsPure {

// Escape a script body for embedding inside single-quoted /bin/sh -c '...'.
// Inside single quotes only the single quote itself needs escaping.
std::string escape(const std::string &script);

}
