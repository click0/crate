// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Shared IP-address / hostname predicates (1.1.30). Before this, private
// copies lived in wireguard_pure, ipsec_pure, migrate_pure, replicate_pure
// and throttle_pure — ipsec_pure even said so ("we duplicate the small
// ones here for clarity ... so this header pulls in no other module").
// That objection is met by keeping this header dependency-free.
//
// The copies were verified semantically identical before consolidation
// (wireguard's `n >= 0 &&` in isV4Octet was a no-op; migrate's isV4
// inlined the same octet check). These are bool predicates only — each
// caller keeps its own error messages.

#pragma once

#include <string>

namespace NetAddrPure {

// One decimal IPv4 octet: 1..3 ASCII digits, value 0..255. Leading
// zeros are accepted ("010"), matching the former copies.
bool isV4Octet(const std::string &s);

// Dotted-quad IPv4: exactly four isV4Octet parts separated by '.'.
bool isV4(const std::string &s);

// Lightweight IPv6: hex groups of 1..4 digits separated by ':', at most
// one "::" shorthand; 8 groups without "::", <= 7 with it. Does not
// accept an embedded IPv4 tail or a %zone suffix.
bool isV6(const std::string &s);

// True iff `s` is dotted-numeric ([0-9.]+ with at least one '.'). Such
// a string must validate as IPv4 — it is never a legal RFC 1123 host
// name (a label can't be all digits), and letting it fall through to
// isHostname would silently accept out-of-range octets like 256.0.0.1.
bool looksLikeV4Shape(const std::string &s);

// RFC 1123 host name: 1..253 chars, dot-separated labels of 1..63
// chars, each label [A-Za-z0-9-] with an alphanumeric first and last
// char. Does not by itself reject all-numeric labels — pair it with
// looksLikeV4Shape (see above).
bool isHostname(const std::string &s);

}
