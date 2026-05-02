// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for the crated export/import endpoints.
//
// The runtime side (daemon/routes.cpp) handles file I/O, libcrate
// invocation, and SHA-256 computation; everything in this header is
// path validation + response formatting + a tiny magic-byte sniffer
// — all unit-testable on Linux.
//

#include <cstdint>
#include <string>

namespace TransferPure {

// Reject filenames that could escape the artifact directory or make
// `/var/run/crate/<name>` ambiguous with daemon state. Rules:
//   - non-empty, ≤ 128 chars
//   - allowed: [A-Za-z0-9._-] (NB: '.' allowed for ".crate" suffix)
//   - reserved: "." and ".."
//   - must NOT contain '/', '\\', NUL, or whitespace
// Returns "" on success; otherwise a one-line reason for the 400.
std::string validateArtifactName(const std::string &name);

// Format a 200 OK JSON body for `POST /export`. `sha256Hex` is the
// SHA-256 of the produced file as 64 lowercase hex characters.
std::string formatExportResponse(const std::string &file,
                                 uint64_t sizeBytes,
                                 const std::string &sha256Hex);

// Format a 200 OK JSON body for `POST /imports/:name`.
std::string formatImportResponse(const std::string &file,
                                 uint64_t sizeBytes,
                                 const std::string &sha256Hex);

// Sniff the leading magic bytes to confirm an uploaded body looks
// like a crate archive (either a plain xz stream or an OpenSSL
// salted blob from `openssl enc -aes-256-cbc -pbkdf2`).
//
// Returns:
//   "xz"        -> 0xFD 0x37 0x7A 0x58 0x5A 0x00
//   "encrypted" -> "Salted__"
//   "unknown"   -> anything else
//
// The runtime uses this to reject obviously-broken uploads before
// hitting libcrate.
const char *sniffArchiveType(const std::string &leadingBytes);

// Build a sha256 hex string from a 32-byte raw digest. Exposed so
// the runtime can inject a real OpenSSL digest while tests can
// supply a deterministic fake without dragging in libcrypto.
std::string hexEncode(const std::string &raw);

} // namespace TransferPure
