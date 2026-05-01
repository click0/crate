// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "sign_pure.h"
#include "err.h"

#include <iomanip>
#include <sys/stat.h>

namespace SignPure {

static void requireRegularNonEmpty(const std::string &path, const char *what,
                                   const struct stat &sb) {
  if (!S_ISREG(sb.st_mode))
    ERR2("sign key", "'" << path << "' (" << what << ") is not a regular file")
  if (sb.st_size == 0)
    ERR2("sign key", "'" << path << "' (" << what << ") is empty")
}

void validateSecretKeyFile(const std::string &path) {
  struct stat sb;
  if (::stat(path.c_str(), &sb) != 0)
    ERR2("sign key", "cannot stat secret key '" << path << "'")
  requireRegularNonEmpty(path, "secret", sb);
  // Reject world / group access — secret keys must be owner-only.
  if (sb.st_mode & (S_IRWXG | S_IRWXO))
    ERR2("sign key",
         "secret key '" << path << "' has loose permissions (mode "
         << std::oct << (sb.st_mode & 0777) << std::dec
         << "); chmod 0600 it first")
}

void validatePublicKeyFile(const std::string &path) {
  struct stat sb;
  if (::stat(path.c_str(), &sb) != 0)
    ERR2("verify key", "cannot stat public key '" << path << "'")
  requireRegularNonEmpty(path, "public", sb);
  // Public keys can be any mode that lets us read them.
}

std::vector<std::string> buildSignArgv(const std::string &secretKey,
                                       const std::string &archive,
                                       const std::string &sigOut) {
  return {
    "/usr/bin/openssl", "pkeyutl",
    "-sign",
    "-inkey", secretKey,
    "-rawin",
    "-in", archive,
    "-out", sigOut,
  };
}

std::vector<std::string> buildVerifyArgv(const std::string &publicKey,
                                         const std::string &archive,
                                         const std::string &sigFile) {
  return {
    "/usr/bin/openssl", "pkeyutl",
    "-verify",
    "-pubin",
    "-inkey", publicKey,
    "-rawin",
    "-in", archive,
    "-sigfile", sigFile,
  };
}

std::string sidecarPath(const std::string &archive) {
  return archive + ".sig";
}

}
