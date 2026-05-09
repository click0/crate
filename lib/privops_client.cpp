// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_client.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef __FreeBSD__
#include <sys/nv.h>
#endif

namespace PrivOpsClient {

namespace {

// Convert a long to its decimal string representation. Hand-rolled
// to keep the pure builders std::ostringstream-free (lighter
// build).
std::string toString(long n) {
  if (n == 0) return "0";
  bool neg = n < 0;
  unsigned long m = neg ? (unsigned long)(-n) : (unsigned long)n;
  std::string out;
  while (m > 0) {
    out.insert(out.begin(), char('0' + (m % 10)));
    m /= 10;
  }
  if (neg) out.insert(out.begin(), '-');
  return out;
}

std::string toString(unsigned u) {
  if (u == 0) return "0";
  std::string out;
  while (u > 0) {
    out.insert(out.begin(), char('0' + (u % 10)));
    u /= 10;
  }
  return out;
}

} // anon

// --- Detection ---

std::string detectSocketPath() {
  // Env var takes priority — operators can override default
  // location for testing or non-standard deployments.
  const char *env = ::getenv("CRATE_PRIVOPS_SOCKET");
  if (env && env[0] != '\0') return env;

  // Well-known default. If file doesn't exist or isn't a socket,
  // skip. This is the dispatch hint for "is rootless wired up
  // on this host?".
  const char *defaultPath = "/var/run/crate/crated-privops.sock";
  struct stat st;
  if (::stat(defaultPath, &st) == 0 && S_ISSOCK(st.st_mode))
    return defaultPath;

  return "";
}

// --- Pure builders ---

PrivOpsNvPure::FieldMap buildSetRctl(long jid,
                                     const std::string &key,
                                     const std::string &rawValue) {
  return {
    {"verb", "set_rctl"},
    {"jid", toString(jid)},
    {"key", key},
    {"value", rawValue},
  };
}

PrivOpsNvPure::FieldMap buildClearRctl(long jid, const std::string &key) {
  return {
    {"verb", "clear_rctl"},
    {"jid", toString(jid)},
    {"key", key},
  };
}

PrivOpsNvPure::FieldMap buildAttachZfs(long jid,
                                       const std::string &dataset) {
  return {
    {"verb", "attach_zfs"},
    {"jid", toString(jid)},
    {"dataset", dataset},
  };
}

PrivOpsNvPure::FieldMap buildDetachZfs(long jid,
                                       const std::string &dataset) {
  return {
    {"verb", "detach_zfs"},
    {"jid", toString(jid)},
    {"dataset", dataset},
  };
}

PrivOpsNvPure::FieldMap buildMountNullfs(const std::string &source,
                                         const std::string &target,
                                         bool readOnly) {
  return {
    {"verb", "mount_nullfs"},
    {"source", source},
    {"target", target},
    {"read_only", readOnly ? "true" : "false"},
  };
}

PrivOpsNvPure::FieldMap buildUnmountNullfs(const std::string &target,
                                           bool force) {
  return {
    {"verb", "unmount_nullfs"},
    {"target", target},
    {"force", force ? "true" : "false"},
  };
}

PrivOpsNvPure::FieldMap buildConfigureIface(long jid,
                                            const std::string &ifname,
                                            const std::string &bridge,
                                            const std::string &ipv4Cidr,
                                            const std::string &ipv6Cidr,
                                            const std::string &macAddr) {
  // Always send all fields — the daemon-side parser distinguishes
  // empty (use default) from unset by absence; sending always
  // matches the JSON wire shape. Empty optionals are simpler than
  // tracking a "do we send this?" flag at every call site.
  return {
    {"verb", "configure_iface"},
    {"jid", toString(jid)},
    {"ifname", ifname},
    {"bridge", bridge},
    {"ipv4_cidr", ipv4Cidr},
    {"ipv6_cidr", ipv6Cidr},
    {"mac_addr", macAddr},
  };
}

PrivOpsNvPure::FieldMap buildTeardownIface(const std::string &ifname) {
  return {
    {"verb", "teardown_iface"},
    {"ifname", ifname},
  };
}

PrivOpsNvPure::FieldMap buildAddPfRule(const std::string &anchor,
                                       const std::string &ruleText) {
  return {
    {"verb", "add_pf_rule"},
    {"anchor", anchor},
    {"rule", ruleText},
  };
}

PrivOpsNvPure::FieldMap buildRemovePfRule(const std::string &anchor,
                                          const std::string &ruleText) {
  return {
    {"verb", "remove_pf_rule"},
    {"anchor", anchor},
    {"rule", ruleText},
  };
}

PrivOpsNvPure::FieldMap buildAddIpfwRule(unsigned set, unsigned number,
                                         const std::string &action,
                                         const std::string &body) {
  return {
    {"verb", "add_ipfw_rule"},
    {"set", toString(set)},
    {"number", toString(number)},
    {"action", action},
    {"body", body},
  };
}

PrivOpsNvPure::FieldMap buildRemoveIpfwRule(unsigned set, unsigned number) {
  return {
    {"verb", "remove_ipfw_rule"},
    {"set", toString(set)},
    {"number", toString(number)},
  };
}

PrivOpsNvPure::FieldMap buildCreateJail(const std::string &name,
                                        const std::string &path,
                                        const std::string &hostname,
                                        bool vnet,
                                        const std::string &parameters) {
  return {
    {"verb", "create_jail"},
    {"name", name},
    {"path", path},
    {"hostname", hostname},
    {"vnet", vnet ? "true" : "false"},
    {"parameters", parameters},
  };
}

PrivOpsNvPure::FieldMap buildDestroyJail(const std::string &name, bool force) {
  return {
    {"verb", "destroy_jail"},
    {"name", name},
    {"force", force ? "true" : "false"},
  };
}

// --- Wire transport (FreeBSD-only) ---

#ifdef __FreeBSD__

namespace {

// Open AF_UNIX socket, connect to socketPath. Returns fd >= 0
// on success, -1 on failure (errno set).
int connectSocket(const std::string &socketPath) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (socketPath.size() >= sizeof(addr.sun_path)) {
    ::close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
  if (::connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int e = errno;
    ::close(fd);
    errno = e;
    return -1;
  }
  return fd;
}

// Walk a FieldMap into an nvlist. Strings only — same convention
// the daemon-side listener uses on the receive side, except the
// listener turns nv numbers/bools into strings during decode and
// here we pack everything as strings during encode. The daemon's
// PrivOpsNvPure parsers handle the type conversion regardless.
nvlist_t *fieldMapToNvlist(const PrivOpsNvPure::FieldMap &fields) {
  nvlist_t *nvl = nvlist_create(0);
  if (!nvl) return nullptr;
  for (const auto &kv : fields)
    nvlist_add_string(nvl, kv.first.c_str(), kv.second.c_str());
  return nvl;
}

} // anon

Response sendRequest(const std::string &socketPath,
                     const PrivOpsNvPure::FieldMap &fields) {
  Response r;
  if (socketPath.empty()) {
    r.transportError = "no privops socket configured";
    return r;
  }

  int fd = connectSocket(socketPath);
  if (fd < 0) {
    r.transportError = std::string("connect ") + socketPath +
                       ": " + ::strerror(errno);
    return r;
  }

  nvlist_t *req = fieldMapToNvlist(fields);
  if (!req) {
    ::close(fd);
    r.transportError = "nvlist_create failed (out of memory?)";
    return r;
  }
  if (nvlist_send(fd, req) != 0) {
    int e = errno;
    nvlist_destroy(req);
    ::close(fd);
    r.transportError = std::string("nvlist_send: ") + ::strerror(e);
    return r;
  }
  nvlist_destroy(req);

  nvlist_t *resp = nvlist_recv(fd, 0);
  ::close(fd);
  if (!resp) {
    r.transportError = std::string("nvlist_recv: ") + ::strerror(errno);
    return r;
  }
  if (nvlist_exists_number(resp, "status"))
    r.status = (int)nvlist_get_number(resp, "status");
  if (nvlist_exists_string(resp, "body"))
    r.body = nvlist_get_string(resp, "body");
  nvlist_destroy(resp);
  return r;
}

#else // !__FreeBSD__

Response sendRequest(const std::string &/*socketPath*/,
                     const PrivOpsNvPure::FieldMap &/*fields*/) {
  Response r;
  r.transportError = "libnv unavailable on this platform "
                     "(FreeBSD required)";
  return r;
}

#endif

} // namespace PrivOpsClient
