// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// The one JSON string escaper (1.1.29). Before this, ten hand-written
// copies lived across lib/, daemon/ and hub/ — each comment saying "same
// shape as audit_pure" — and two of them had drifted into emitting
// invalid JSON (fixed in 1.1.27). They now all delegate here.
//
// Deliberately dependency-free (no util.h): pure modules include this
// without pulling in util.h's fan-in.

#pragma once

#include <string>

namespace JsonPure {

// Escape `s` for use INSIDE a JSON string literal (no surrounding
// quotes). RFC 8259: `"` and `\` are escaped; \b \f \n \r \t use their
// short forms; every other byte < 0x20 becomes \u00XX (lowercase hex).
// Bytes >= 0x20 — including DEL and UTF-8 multibyte sequences — pass
// through unchanged: they are legal inside a JSON string.
std::string escape(const std::string &s);

// escape() wrapped in double quotes — a complete JSON string value.
std::string quote(const std::string &s);

}
