// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Capsicum sandbox using libcasper.

#include "capsicum_ops.h"
#include "err.h"

#include <rang.hpp>

#ifdef HAVE_CAPSICUM
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/capsicum.h>
#include <libcasper.h>
#include <casper/cap_dns.h>
#include <casper/cap_syslog.h>
#include <netdb.h>
#include <syslog.h>
#endif

#include <string.h>
#include <syslog.h>

#define WARN(msg...) \
  std::cerr << rang::fg::yellow << msg << rang::style::reset << std::endl;

namespace CapsicumOps {

#ifdef HAVE_CAPSICUM
static cap_channel_t *g_casper = nullptr;
static cap_channel_t *g_capdns = nullptr;
static cap_channel_t *g_capsyslog = nullptr;

static cap_channel_t *getCasper() {
  if (!g_casper) {
    g_casper = cap_init();
    if (!g_casper)
      return nullptr;
  }
  return g_casper;
}
#endif

bool available() {
#ifdef HAVE_CAPSICUM
  return true;
#else
  return false;
#endif
}

bool enterCapabilityMode() {
#ifdef HAVE_CAPSICUM
  if (::cap_enter() == -1)
    return false;
  return true;
#else
  return false;
#endif
}

bool initCapDns() {
#ifdef HAVE_CAPSICUM
  auto *casper = getCasper();
  if (!casper) return false;

  g_capdns = cap_service_open(casper, "system.dns");
  if (!g_capdns) return false;

  // Limit to name resolution only
  const char *types[] = {"ADDR"};
  cap_dns_type_limit(g_capdns, types, 1);

  return true;
#else
  return false;
#endif
}

bool initCapSyslog() {
#ifdef HAVE_CAPSICUM
  auto *casper = getCasper();
  if (!casper) return false;

  g_capsyslog = cap_service_open(casper, "system.syslog");
  if (!g_capsyslog) return false;
  return true;
#else
  return false;
#endif
}

std::string resolveDns(const std::string &hostname) {
#ifdef HAVE_CAPSICUM
  if (!g_capdns) return "";

  struct addrinfo hints = {};
  hints.ai_family = AF_INET;
  struct addrinfo *res = nullptr;

  if (cap_getaddrinfo(g_capdns, hostname.c_str(), nullptr, &hints, &res) != 0)
    return "";

  char buf[INET_ADDRSTRLEN];
  struct sockaddr_in *sa = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
  ::inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
  ::freeaddrinfo(res);
  return std::string(buf);
#else
  (void)hostname;
  return "";
#endif
}

void logSyslog(int priority, const std::string &msg) {
#ifdef HAVE_CAPSICUM
  if (g_capsyslog)
    cap_syslog(g_capsyslog, priority, "%s", msg.c_str());
  else
#endif
    ::syslog(priority, "%s", msg.c_str());
}

bool limitFdRights(int fd, unsigned long long rights) {
#ifdef HAVE_CAPSICUM
  cap_rights_t r;
  cap_rights_init(&r, rights);
  return ::cap_rights_limit(fd, &r) == 0;
#else
  (void)fd; (void)rights;
  return false;
#endif
}

}
