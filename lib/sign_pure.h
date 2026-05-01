// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers for ed25519 signing/verification of .crate archives.
//
// Format
// ------
// Signatures are produced by `openssl pkeyutl -sign -rawin -inkey
// <ed25519-key>` and stored as a sidecar `<archive>.sig` (64 bytes,
// raw binary). Verification uses the matching public key with
// `openssl pkeyutl -verify -pubin -inkey <pub>`.
//
// The signature covers the **on-disk archive bytes** (including any
// AES-256-CBC encryption layer added by 0.5.4). That means:
//   * a tampered ciphertext is detected by signature
//   * the public key can verify provenance without holding the
//     passphrase
//   * the .sha256 sidecar still works as a content-addressed lookup
//
// Threat model
// ------------
// ed25519 ratifies AUTHENTICITY (this archive was signed by the
// holder of the secret key). It does not by itself establish
// confidentiality — pair with the existing -P passphrase if the
// archive must travel over an untrusted channel.

#pragma once

#include <string>
#include <vector>

namespace SignPure {

// Validate that `path` exists, is a regular non-empty file, and has
// owner-only permissions (0600 or stricter). Used for ed25519 SECRET
// keys. Throws on failure.
void validateSecretKeyFile(const std::string &path);

// Validate that `path` exists, is a regular non-empty file. Public
// keys may be world-readable (mode 0644 is fine). Throws on failure.
void validatePublicKeyFile(const std::string &path);

// Build openssl argv for signing `archive` with `secretKey`, writing
// the raw 64-byte signature to `sigOut`.
std::vector<std::string> buildSignArgv(const std::string &secretKey,
                                       const std::string &archive,
                                       const std::string &sigOut);

// Build openssl argv to verify `sigFile` against `archive` using
// `publicKey`. openssl exits 0 on valid, non-zero on mismatch.
std::vector<std::string> buildVerifyArgv(const std::string &publicKey,
                                         const std::string &archive,
                                         const std::string &sigFile);

// Conventional sidecar path: "<archive>.sig".
std::string sidecarPath(const std::string &archive);

}
