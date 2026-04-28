// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "auth.h"
#include "auth_pure.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <openssl/sha.h>

#include <sys/socket.h>
#include <sys/ucred.h>
#include <unistd.h>

#include <iomanip>
#include <sstream>

namespace Crated {

static std::string sha256hex(const std::string &input) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
  std::ostringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
  return "sha256:" + ss.str();
}

// Check if request comes from a Unix socket by examining peer credentials.
// FreeBSD provides getpeereid(2) for Unix domain sockets.
static bool isUnixSocketPeer(const httplib::Request &req) {
  auto remoteAddr = req.get_header_value("REMOTE_ADDR");
  return remoteAddr.empty();
}

// Verify Unix socket peer credentials using getpeereid(2).
// Returns true if the peer is root (uid 0) or in the wheel group.
static bool checkUnixPeerCredentials(int fd) {
  if (fd < 0)
    return false;

  uid_t euid;
  gid_t egid;
  if (getpeereid(fd, &euid, &egid) == 0)
    return euid == 0 || egid == 0;
  return false;
}

bool isAuthorized(const httplib::Request &req, const Config &config,
                  const std::string &requiredRole) {
  if (isUnixSocketPeer(req))
    return true;

  // Bearer-token check via pure helper (lib/auth_pure.cpp).
  return AuthPure::checkBearerAuth(
    req.get_header_value("Authorization"),
    config.tokens,
    requiredRole,
    sha256hex);
}

}
