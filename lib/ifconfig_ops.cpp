// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Network interface operations using libifconfig with fallback to ifconfig(8).

#include "ifconfig_ops.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#ifdef HAVE_LIBIFCONFIG
#include <libifconfig.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_bridgevar.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include <sstream>
#include <string>

#define ERR(msg...) ERR2("ifconfig", msg)

namespace IfconfigOps {

// ---------------------------------------------------------------------------
// libifconfig handle (singleton)
// ---------------------------------------------------------------------------

#ifdef HAVE_LIBIFCONFIG

static ifconfig_handle_t *getHandle() {
  static ifconfig_handle_t *h = nullptr;
  if (!h) {
    h = ifconfig_open();
    if (!h)
      return nullptr;
    static struct Cleanup {
      ~Cleanup() { if (h) { ifconfig_close(h); h = nullptr; } }
    } cleanup;
  }
  return h;
}

#endif

bool available() {
#ifdef HAVE_LIBIFCONFIG
  return getHandle() != nullptr;
#else
  return false;
#endif
}

// ---------------------------------------------------------------------------
// Helper: simple ioctl socket
// ---------------------------------------------------------------------------

static int getIoctlSocket() {
  static int s = -1;
  if (s < 0) {
    s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
      static struct Cleanup {
        ~Cleanup() { if (s >= 0) { ::close(s); s = -1; } }
      } cleanup;
    }
  }
  return s;
}

// ---------------------------------------------------------------------------
// Create / Destroy interfaces
// ---------------------------------------------------------------------------

std::pair<std::string, std::string> createEpair() {
#ifdef HAVE_LIBIFCONFIG
  auto *h = getHandle();
  if (h) {
    char name[IFNAMSIZ] = "epair";
    if (ifconfig_create_interface(h, name, &name) == 0) {
      // name is now e.g. "epair0a"
      std::string a(name);
      // b side: replace trailing 'a' with 'b'
      std::string b = a;
      if (!b.empty() && b.back() == 'a')
        b.back() = 'b';
      return {a, b};
    }
    // Fall through to command fallback
  }
#endif
  auto output = Util::execCommandGetOutput(
    {CRATE_PATH_IFCONFIG, "epair", "create"}, "create epair");
  // Strip trailing newline
  while (!output.empty() && (output.back() == '\n' || output.back() == '\r'))
    output.pop_back();
  // output is e.g. "epair0a"
  std::string a = output;
  std::string b = a;
  if (!b.empty() && b.back() == 'a')
    b.back() = 'b';
  return {a, b};
}

void destroyInterface(const std::string &name) {
#ifdef HAVE_LIBIFCONFIG
  auto *h = getHandle();
  if (h) {
    if (ifconfig_destroy_interface(h, name.c_str()) == 0)
      return;
  }
#endif
  Util::execCommand({CRATE_PATH_IFCONFIG, name, "destroy"},
    STR("destroy interface " << name));
}

// ---------------------------------------------------------------------------
// IP address assignment
// ---------------------------------------------------------------------------

void setInetAddr(const std::string &iface, const std::string &addr, int prefixLen) {
#ifdef HAVE_LIBIFCONFIG
  auto *h = getHandle();
  if (h) {
    struct sockaddr_in sin = {};
    sin.sin_len = sizeof(sin);
    sin.sin_family = AF_INET;
    ::inet_pton(AF_INET, addr.c_str(), &sin.sin_addr);

    struct sockaddr_in mask = {};
    mask.sin_len = sizeof(mask);
    mask.sin_family = AF_INET;
    uint32_t m = prefixLen ? (~0U << (32 - prefixLen)) : 0;
    mask.sin_addr.s_addr = htonl(m);

    if (ifconfig_set_addr(h, iface.c_str(),
                          reinterpret_cast<struct sockaddr*>(&sin),
                          reinterpret_cast<struct sockaddr*>(&mask)) == 0)
      return;
  }
#endif
  Util::execCommand(
    {CRATE_PATH_IFCONFIG, iface, "inet", STR(addr << "/" << prefixLen)},
    STR("set IP on " << iface));
}

void setInet6Addr(const std::string &iface, const std::string &addr, int prefixLen) {
  // No simple libifconfig API for IPv6 — use command
  Util::execCommand(
    {CRATE_PATH_IFCONFIG, iface, "inet6", STR(addr << "/" << prefixLen)},
    STR("set IPv6 on " << iface));
}

// ---------------------------------------------------------------------------
// VNET
// ---------------------------------------------------------------------------

void moveToVnet(const std::string &iface, int jid) {
  // libifconfig doesn't have a direct VNET API; use ioctl SIOCSIFVNET
  int s = getIoctlSocket();
  if (s >= 0) {
    struct ifreq ifr = {};
    ::strlcpy(ifr.ifr_name, iface.c_str(), sizeof(ifr.ifr_name));
    ifr.ifr_jid = jid;
    if (::ioctl(s, SIOCSIFVNET, &ifr) == 0)
      return;
    // Fall through to command
  }
  Util::execCommand(
    {CRATE_PATH_IFCONFIG, iface, "vnet", std::to_string(jid)},
    STR("move " << iface << " to vnet jail " << jid));
}

// ---------------------------------------------------------------------------
// Offloading control
// ---------------------------------------------------------------------------

void disableOffload(const std::string &iface) {
#ifdef HAVE_LIBIFCONFIG
  auto *h = getHandle();
  if (h) {
    // Try to clear offload capabilities
    if (ifconfig_unset_ifcap(h, iface.c_str(), IFCAP_TXCSUM | IFCAP_RXCSUM) == 0)
      return;
  }
#endif
  // Fallback: run multiple ifconfig commands
  try {
    Util::execCommand(
      {CRATE_PATH_IFCONFIG, iface, "-txcsum", "-rxcsum", "-txcsum6", "-rxcsum6"},
      STR("disable offload on " << iface));
  } catch (...) {
    // Best-effort: some flags may not exist on all interface types
  }
}

void disableLroTso(const std::string &iface) {
  try {
    Util::execCommand(
      {CRATE_PATH_IFCONFIG, iface, "-lro", "-tso"},
      STR("disable LRO/TSO on " << iface));
  } catch (...) {}
}

// ---------------------------------------------------------------------------
// Bridge operations
// ---------------------------------------------------------------------------

void bridgeAddMember(const std::string &bridge, const std::string &member) {
  // Use ioctl BRDGADD
  int s = getIoctlSocket();
  if (s >= 0) {
    struct ifbreq req = {};
    ::strlcpy(req.ifbr_ifsname, member.c_str(), sizeof(req.ifbr_ifsname));
    struct ifdrv ifd = {};
    ::strlcpy(ifd.ifd_name, bridge.c_str(), sizeof(ifd.ifd_name));
    ifd.ifd_cmd = BRDGADD;
    ifd.ifd_len = sizeof(req);
    ifd.ifd_data = &req;
    if (::ioctl(s, SIOCSDRVSPEC, &ifd) == 0)
      return;
    // Fall through
  }
  Util::execCommand(
    {CRATE_PATH_IFCONFIG, bridge, "addm", member},
    STR("add " << member << " to bridge " << bridge));
}

void bridgeDelMember(const std::string &bridge, const std::string &member) {
  int s = getIoctlSocket();
  if (s >= 0) {
    struct ifbreq req = {};
    ::strlcpy(req.ifbr_ifsname, member.c_str(), sizeof(req.ifbr_ifsname));
    struct ifdrv ifd = {};
    ::strlcpy(ifd.ifd_name, bridge.c_str(), sizeof(ifd.ifd_name));
    ifd.ifd_cmd = BRDGDEL;
    ifd.ifd_len = sizeof(req);
    ifd.ifd_data = &req;
    if (::ioctl(s, SIOCSDRVSPEC, &ifd) == 0)
      return;
  }
  Util::execCommand(
    {CRATE_PATH_IFCONFIG, bridge, "deletem", member},
    STR("remove " << member << " from bridge " << bridge));
}

// ---------------------------------------------------------------------------
// UP/DOWN, MAC, description
// ---------------------------------------------------------------------------

void setUp(const std::string &iface) {
  int s = getIoctlSocket();
  if (s >= 0) {
    struct ifreq ifr = {};
    ::strlcpy(ifr.ifr_name, iface.c_str(), sizeof(ifr.ifr_name));
    if (::ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
      ifr.ifr_flags |= IFF_UP;
      if (::ioctl(s, SIOCSIFFLAGS, &ifr) == 0)
        return;
    }
  }
  Util::execCommand({CRATE_PATH_IFCONFIG, iface, "up"},
    STR("bring up " << iface));
}

void setDown(const std::string &iface) {
  int s = getIoctlSocket();
  if (s >= 0) {
    struct ifreq ifr = {};
    ::strlcpy(ifr.ifr_name, iface.c_str(), sizeof(ifr.ifr_name));
    if (::ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
      ifr.ifr_flags &= ~IFF_UP;
      if (::ioctl(s, SIOCSIFFLAGS, &ifr) == 0)
        return;
    }
  }
  Util::execCommand({CRATE_PATH_IFCONFIG, iface, "down"},
    STR("bring down " << iface));
}

void setMacAddr(const std::string &iface, const unsigned char mac[6]) {
  char macStr[18];
  ::snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  Util::execCommand(
    {CRATE_PATH_IFCONFIG, iface, "link", macStr},
    STR("set MAC on " << iface));
}

void setMacAddr(const std::string &iface, const std::string &mac) {
  Util::execCommand(
    {CRATE_PATH_IFCONFIG, iface, "ether", mac},
    STR("set MAC on " << iface));
}

void setDescription(const std::string &iface, const std::string &desc) {
  Util::execCommand(
    {CRATE_PATH_IFCONFIG, iface, "description", desc},
    STR("set description on " << iface));
}

std::string createVlan(const std::string &parentIface, int vlanId) {
  auto output = Util::execCommandGetOutput(
    {CRATE_PATH_IFCONFIG, STR(parentIface << "." << vlanId), "create",
     "vlan", std::to_string(vlanId), "vlandev", parentIface},
    "create VLAN");
  while (!output.empty() && output.back() == '\n') output.pop_back();
  return output.empty() ? STR(parentIface << "." << vlanId) : output;
}

}
