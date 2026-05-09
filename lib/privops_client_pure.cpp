// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_client.h"

#include <cstdlib>
#include <string>

#include <sys/stat.h>

//
// Pure half of privops_client (0.9.16, hotfix split from 0.9.15).
//
// Why split:
//   - 0.9.15 put builders + detection + sendRequest in one file
//     and added the file to TEST_LINK_SRCS so tests could see the
//     builders. On FreeBSD that pulled `<sys/nv.h>` symbols
//     (nvlist_send/recv etc.) into every test binary's link line.
//     The lite CI's `gmake build-unit-tests` step failed because
//     the test link didn't pull -lnv (nor explicit libc nvlist
//     deps depending on FreeBSD version). Linux unit tests passed
//     because the #else branch has no libnv refs.
//   - This file owns ONLY the pure pieces (no syscalls beyond
//     stat(2), no libnv): 14 verb builders + detectSocketPath +
//     stringification helpers. Goes into BOTH LIB_SRCS and
//     TEST_LINK_SRCS — tests see the builders, no libnv leak.
//   - Wire send (`sendRequest`) lives in lib/privops_client.cpp,
//     LIB_SRCS only. Tests can't call sendRequest directly any
//     more; the two send_returns_transport_error_* tests from
//     0.9.15 were dropped (the early-return path is uninteresting
//     and the post-connect path needs a real daemon to exercise).
//

namespace PrivOpsClient {

namespace {

// Hand-rolled itoa to keep the builders std::ostringstream-free
// (lighter test-binary build).
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
  const char *env = ::getenv("CRATE_PRIVOPS_SOCKET");
  if (env && env[0] != '\0') return env;

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

} // namespace PrivOpsClient
