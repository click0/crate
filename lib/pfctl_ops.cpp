// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// PF firewall operations using libpfctl with pfctl(8) fallback.

#include "pfctl_ops.h"
#include "spec.h"
#include "net.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#ifdef HAVE_LIBPFCTL
#include <libpfctl.h>
#endif

#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <sstream>

#define ERR(msg...) ERR2("pfctl", msg)

namespace PfctlOps {

#ifdef HAVE_LIBPFCTL
static int openPfDev() {
  static int fd = -1;
  if (fd < 0) {
    fd = ::open("/dev/pf", O_RDWR);
    if (fd >= 0) {
      static struct Cleanup {
        ~Cleanup() { if (fd >= 0) { ::close(fd); fd = -1; } }
      } cleanup;
    }
  }
  return fd;
}
#endif

bool available() {
#ifdef HAVE_LIBPFCTL
  return openPfDev() >= 0;
#else
  return false;
#endif
}

void addRules(const std::string &anchor, const std::vector<std::string> &rules) {
#ifdef HAVE_LIBPFCTL
  int fd = openPfDev();
  if (fd >= 0) {
    // Build rules string
    std::ostringstream ss;
    for (auto &r : rules)
      ss << r << "\n";
    auto rulesStr = ss.str();

    struct pfctl_handle *ph = pfctl_open(fd);
    if (ph) {
      // Load rules into anchor
      int err = pfctl_add_rules(ph, rulesStr.c_str(), rulesStr.size(),
                                anchor.c_str(), PF_RULESET_FILTER);
      pfctl_close(ph);
      if (err == 0) return;
    }
  }
#endif
  // Fallback: echo rules | pfctl -a <anchor> -f -
  std::ostringstream ss;
  for (auto &r : rules)
    ss << r << "\n";
  auto rulesStr = ss.str();

  // Write rules to a temp file, then load
  auto tmpFile = STR("/tmp/crate-pf-" << ::getpid() << ".rules");
  Util::Fs::writeFile(rulesStr, tmpFile);
  try {
    Util::execCommand({CRATE_PATH_PFCTL, "-a", anchor, "-f", tmpFile},
      STR("load PF rules into anchor " << anchor));
  } catch (...) {
    Util::Fs::unlink(tmpFile);
    throw;
  }
  Util::Fs::unlink(tmpFile);
}

void addRules(const std::string &anchor, const std::string &rulesText) {
  // Write rules to a temp file, then load
  auto tmpFile = STR("/tmp/crate-pf-" << ::getpid() << ".rules");
  Util::Fs::writeFile(rulesText, tmpFile);
  try {
    Util::execCommand({CRATE_PATH_PFCTL, "-a", anchor, "-f", tmpFile},
      STR("load PF rules into anchor " << anchor));
  } catch (...) {
    Util::Fs::unlink(tmpFile);
    throw;
  }
  Util::Fs::unlink(tmpFile);
}

void flushRules(const std::string &anchor) {
#ifdef HAVE_LIBPFCTL
  int fd = openPfDev();
  if (fd >= 0) {
    struct pfctl_handle *ph = pfctl_open(fd);
    if (ph) {
      pfctl_clear_rules(ph, anchor.c_str(), PF_RULESET_FILTER);
      pfctl_clear_rules(ph, anchor.c_str(), PF_RULESET_NAT);
      pfctl_close(ph);
      return;
    }
  }
#endif
  try {
    Util::execCommand({CRATE_PATH_PFCTL, "-a", anchor, "-F", "all"},
      STR("flush PF anchor " << anchor));
  } catch (const std::exception &e) {
    WARN("failed to flush pf anchor '" << anchor << "': " << e.what())
  } catch (...) {
    WARN("failed to flush pf anchor '" << anchor << "'")
  }
}

std::string loadContainerPolicy(const Spec &spec,
                                const std::string &jailXname,
                                const std::string &ipv4,
                                const std::string &ipv6) {
  if (!spec.firewallPolicy)
    return {};

  auto anchorName = STR("crate/" << jailXname);
  bool hasV6 = !ipv6.empty();
  std::ostringstream pf;

  for (auto &cidr : spec.firewallPolicy->blockIp) {
    pf << "block drop quick from " << ipv4 << " to " << cidr << "\n";
    if (hasV6) {
      auto slash = cidr.find('/');
      auto addr = (slash != std::string::npos) ? cidr.substr(0, slash) : cidr;
      if (Net::isIpv6Address(addr))
        pf << "block drop quick from " << ipv6 << " to " << cidr << "\n";
    }
  }

  for (auto port : spec.firewallPolicy->allowTcp) {
    pf << "pass out quick proto tcp from " << ipv4 << " to any port " << port << "\n";
    if (hasV6)
      pf << "pass out quick inet6 proto tcp from " << ipv6 << " to any port " << port << "\n";
  }

  for (auto port : spec.firewallPolicy->allowUdp) {
    pf << "pass out quick proto udp from " << ipv4 << " to any port " << port << "\n";
    if (hasV6)
      pf << "pass out quick inet6 proto udp from " << ipv6 << " to any port " << port << "\n";
  }

  if (spec.firewallPolicy->defaultPolicy == "block")
    pf << "block drop all\n";
  else
    pf << "pass all\n";

  addRules(anchorName, pf.str());
  return anchorName;
}

}
