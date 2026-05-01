// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure helpers for the .crate archive encryption envelope.
//
// Format
// ------
// Encrypted archives are produced by piping the plain xz-compressed
// tar through `openssl enc -aes-256-cbc -pbkdf2 -salt`. OpenSSL writes
// an 8-byte "Salted__" magic prefix followed by 8 bytes of salt, then
// the ciphertext. We detect encryption on import by reading the first
// 8 bytes:
//   "Salted__"           -> Encrypted (AES-256-CBC + PBKDF2)
//   0xfd 0x37 0x7a 0x58  -> Plain (xz magic)
//   anything else        -> Unknown / corrupt
//
// Authenticity is provided by the existing .sha256 sidecar file —
// AES-CBC alone is not authenticated, so the operator MUST verify the
// SHA256 checksum from a trusted out-of-band source before decrypting.

#pragma once

#include <string>
#include <vector>

namespace CryptoPure {

enum class Format { Plain, Encrypted, Unknown };

// Inspect the first bytes of a file to decide whether it is plain or
// encrypted. Returns Unknown for input shorter than 6 bytes or with a
// magic that matches neither.
Format detectFormat(const std::string &firstBytes);
Format detectFile(const std::string &path);

// Validate that `path` exists, is a regular file, is non-empty, and
// has restrictive permissions (no world / group access). Throws on
// failure with a human-readable message.
void validatePassphraseFile(const std::string &path);

// Build the openssl enc command line for encryption / decryption.
// `passphraseFile` will be passed via `-kfile <path>` so the secret
// never appears on the process command line.
std::vector<std::string> buildEncryptArgv(const std::string &passphraseFile);
std::vector<std::string> buildDecryptArgv(const std::string &passphraseFile);

}
