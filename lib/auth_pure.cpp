// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "auth_pure.h"

#include <cstring>
#include <ctime>

namespace AuthPure {

std::string parseBearerToken(const std::string &authHeader) {
  static const std::string prefix = "Bearer ";
  if (authHeader.size() <= prefix.size())
    return "";
  if (authHeader.compare(0, prefix.size(), prefix) != 0)
    return "";
  return authHeader.substr(prefix.size());
}

bool checkTokenRole(const std::string &tokenHash,
                    const std::vector<Crated::AuthToken> &tokens,
                    const std::string &requiredRole) {
  for (auto &t : tokens) {
    if (t.tokenHash == tokenHash) {
      if (requiredRole == "viewer")
        return true;
      return t.role == requiredRole || t.role == "admin";
    }
  }
  return false;
}

bool checkBearerAuth(const std::string &authHeader,
                     const std::vector<Crated::AuthToken> &tokens,
                     const std::string &requiredRole,
                     const std::function<std::string(const std::string&)> &sha256Fn) {
  auto token = parseBearerToken(authHeader);
  if (token.empty())
    return false;
  auto hash = sha256Fn(token);
  return checkTokenRole(hash, tokens, requiredRole);
}

// --- TTL + scope ---

long parseIso8601Utc(const std::string &s) {
  // Accept "YYYY-MM-DDTHH:MM:SSZ" and "YYYY-MM-DDTHH:MM:SS+00:00".
  // Reject anything with a non-zero offset — we want UTC only.
  std::tm tm{};
  // Parse the YMDHMS prefix (19 chars).
  if (s.size() < 20) return -1;
  if (s[4] != '-' || s[7] != '-' || s[10] != 'T'
      || s[13] != ':' || s[16] != ':')
    return -1;
  for (int i : {0,1,2,3,5,6,8,9,11,12,14,15,17,18}) {
    if (s[i] < '0' || s[i] > '9') return -1;
  }
  tm.tm_year = std::atoi(s.substr(0, 4).c_str()) - 1900;
  tm.tm_mon  = std::atoi(s.substr(5, 2).c_str()) - 1;
  tm.tm_mday = std::atoi(s.substr(8, 2).c_str());
  tm.tm_hour = std::atoi(s.substr(11, 2).c_str());
  tm.tm_min  = std::atoi(s.substr(14, 2).c_str());
  tm.tm_sec  = std::atoi(s.substr(17, 2).c_str());
  // Sanity-check ranges before timegm so 99-99-99 etc. are rejected.
  if (tm.tm_mon < 0 || tm.tm_mon > 11) return -1;
  if (tm.tm_mday < 1 || tm.tm_mday > 31) return -1;
  if (tm.tm_hour < 0 || tm.tm_hour > 23) return -1;
  if (tm.tm_min < 0  || tm.tm_min  > 59) return -1;
  if (tm.tm_sec < 0  || tm.tm_sec  > 60) return -1;
  // Timezone suffix.
  auto tz = s.substr(19);
  if (tz != "Z" && tz != "+00:00" && tz != "-00:00") return -1;
  long t = (long)::timegm(&tm);
  return t;
}

bool isExpired(const Crated::AuthToken &t, long now) {
  if (t.expiresAt == 0) return false;     // 0 == "never expires"
  return now > t.expiresAt;
}

bool pathInScope(const std::vector<std::string> &scope,
                 const std::string &path) {
  if (scope.empty()) return true;          // empty == no restriction
  for (auto &p : scope) {
    if (p.empty()) continue;
    // Trailing-glob: pattern ending in "/*" matches any path that
    // starts with the prefix INCLUDING the slash. So "/api/v1/foo/*"
    // matches "/api/v1/foo/bar" but NOT "/api/v1/foo".
    if (p.size() >= 2 && p.compare(p.size() - 2, 2, "/*") == 0) {
      auto prefix = p.substr(0, p.size() - 1);  // keep trailing '/'
      if (path.size() > prefix.size()
          && path.compare(0, prefix.size(), prefix) == 0)
        return true;
      continue;
    }
    if (path == p) return true;
  }
  return false;
}

bool checkBearerAuthFull(const std::string &authHeader,
                         const std::vector<Crated::AuthToken> &tokens,
                         const std::string &requiredRole,
                         const std::string &path,
                         long now,
                         const std::function<std::string(const std::string&)> &sha256Fn) {
  auto token = parseBearerToken(authHeader);
  if (token.empty()) return false;
  auto hash = sha256Fn(token);
  // Find matching entry to check expiry + scope before returning.
  for (auto &t : tokens) {
    if (t.tokenHash != hash) continue;
    if (isExpired(t, now))                              return false;
    if (!pathInScope(t.scope, path))                    return false;
    if (requiredRole == "viewer")                       return true;
    return t.role == requiredRole || t.role == "admin";
  }
  return false;
}

}
