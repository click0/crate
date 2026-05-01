// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "crypto_pure.h"
#include "err.h"

#include <cstring>
#include <fstream>
#include <sys/stat.h>

namespace CryptoPure {

// "Salted__" — OpenSSL `enc` magic prefix (8 bytes).
static const char kOpensslSalted[] = {'S','a','l','t','e','d','_','_'};
// xz magic: 0xFD '7' 'z' 'X' 'Z' 0x00
static const unsigned char kXzMagic[] = {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00};

Format detectFormat(const std::string &firstBytes) {
  if (firstBytes.size() >= sizeof(kOpensslSalted) &&
      std::memcmp(firstBytes.data(), kOpensslSalted, sizeof(kOpensslSalted)) == 0)
    return Format::Encrypted;
  if (firstBytes.size() >= sizeof(kXzMagic) &&
      std::memcmp(firstBytes.data(), kXzMagic, sizeof(kXzMagic)) == 0)
    return Format::Plain;
  return Format::Unknown;
}

Format detectFile(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  if (!f.good()) return Format::Unknown;
  char buf[8] = {0};
  f.read(buf, sizeof(buf));
  return detectFormat(std::string(buf, static_cast<size_t>(f.gcount())));
}

void validatePassphraseFile(const std::string &path) {
  struct stat sb;
  if (::stat(path.c_str(), &sb) != 0)
    ERR2("passphrase file", "cannot stat '" << path << "'")
  if (!S_ISREG(sb.st_mode))
    ERR2("passphrase file", "'" << path << "' is not a regular file")
  if (sb.st_size == 0)
    ERR2("passphrase file", "'" << path << "' is empty")
  // Reject world- and group-readable: passphrases must be owner-only.
  if (sb.st_mode & (S_IRWXG | S_IRWXO))
    ERR2("passphrase file",
         "'" << path << "' has loose permissions (mode "
         << std::oct << (sb.st_mode & 0777) << std::dec
         << "); chmod 0600 it first")
}

std::vector<std::string> buildEncryptArgv(const std::string &passphraseFile) {
  return {
    "/usr/bin/openssl", "enc",
    "-e",
    "-aes-256-cbc",
    "-pbkdf2",
    "-salt",
    "-kfile", passphraseFile,
  };
}

std::vector<std::string> buildDecryptArgv(const std::string &passphraseFile) {
  return {
    "/usr/bin/openssl", "enc",
    "-d",
    "-aes-256-cbc",
    "-pbkdf2",
    "-kfile", passphraseFile,
  };
}

}
