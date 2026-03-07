// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// PF firewall operations using libpfctl with pfctl(8) fallback.

#include "pfctl_ops.h"
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
  } catch (...) {
    // Best effort — anchor may not exist
  }
}

void addNatRule(const std::string &anchor,
                const std::string &srcNet, const std::string &natAddr) {
  auto rule = STR("nat on egress from " << srcNet << " to any -> " << natAddr);
  addRules(anchor, {rule});
}

void addRdrRule(const std::string &anchor,
                const std::string &extAddr, int extPort,
                const std::string &intAddr, int intPort,
                const std::string &proto) {
  auto rule = STR("rdr on egress proto " << proto
                  << " from any to " << extAddr << " port " << extPort
                  << " -> " << intAddr << " port " << intPort);
  addRules(anchor, {rule});
}

}
