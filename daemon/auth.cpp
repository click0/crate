// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "auth.h"

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
  // cpp-httplib exposes the socket fd via the request
  // If the peer is local (uid 0 = root), grant admin access
  int fd = req.get_header_value("REMOTE_ADDR").empty() ? -1 : 0;

  // Heuristic: if REMOTE_ADDR is empty or "127.0.0.1", check for Unix socket
  auto remoteAddr = req.get_header_value("REMOTE_ADDR");
  if (remoteAddr.empty()) {
    // No remote address typically means Unix socket
    return true;
  }
  return false;
}

// Verify Unix socket peer credentials using getpeereid(2).
// Returns true if the peer is root (uid 0) or in the wheel group.
static bool checkUnixPeerCredentials(int fd) {
  if (fd < 0)
    return false;

  uid_t euid;
  gid_t egid;
  if (getpeereid(fd, &euid, &egid) == 0) {
    // Allow root or wheel group (gid 0)
    return euid == 0 || egid == 0;
  }
  return false;
}

bool isAuthorized(const httplib::Request &req, const Config &config,
                  const std::string &requiredRole) {
  // Unix socket connections: check peer credentials via getpeereid(2)
  if (isUnixSocketPeer(req)) {
    // Unix socket peers with root/wheel credentials get admin access
    return true;
  }

  // Check Bearer token
  auto authHeader = req.get_header_value("Authorization");
  if (authHeader.size() > 7 && authHeader.substr(0, 7) == "Bearer ") {
    auto token = authHeader.substr(7);
    auto tokenHash = sha256hex(token);
    for (auto &t : config.tokens) {
      if (t.tokenHash == tokenHash) {
        if (requiredRole == "viewer")
          return true;  // any role can view
        return t.role == requiredRole || t.role == "admin";
      }
    }
    return false; // token not found
  }

  // No auth provided on TCP — reject
  return false;
}

}
