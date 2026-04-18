// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// IPFW operations via raw socket with IP_FW3 setsockopt, ipfw(8) fallback.

#include "ipfw_ops.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

// FreeBSD IPFW kernel interface
#include <netinet/ip_fw.h>

#include <string>
#include <sstream>
#include <vector>
#include <chrono>
#include <iostream>

#define ERR(msg...) ERR2("ipfw", msg)

namespace IpfwOps {

// --- Native IP_FW3 API ---

// RAII wrapper for raw socket
class IpfwSocket {
public:
  IpfwSocket() : fd_(::socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) {}
  ~IpfwSocket() { if (fd_ >= 0) ::close(fd_); }
  int fd() const { return fd_; }
  bool valid() const { return fd_ >= 0; }
private:
  int fd_;
};

// Perform an IP_FW3 setsockopt call
static bool ipfw3Set(int fd, uint32_t opcode, void *data, socklen_t len) {
  ip_fw3_opheader *op = (ip_fw3_opheader *)data;
  op->opcode = opcode;
  op->ctxid = 0;  // default context
  return ::setsockopt(fd, IPPROTO_IP, IP_FW3, data, len) == 0;
}

// Perform an IP_FW3 getsockopt call
static bool ipfw3Get(int fd, uint32_t opcode, void *data, socklen_t *len) {
  ip_fw3_opheader *op = (ip_fw3_opheader *)data;
  op->opcode = opcode;
  op->ctxid = 0;
  return ::getsockopt(fd, IPPROTO_IP, IP_FW3, data, len) == 0;
}

// --- Runtime detection: native vs shell ---

static bool g_nativeDetected = false;
static bool g_nativeAvailable = false;

// Probe the IP_FW3 kernel interface with a non-destructive operation.
// Opens a raw socket and attempts IP_FW_XGET to check if IPFW is loaded
// and the kernel supports the native API.  Result is cached for the
// lifetime of the process.
bool useNativeApi() {
  if (!g_nativeDetected) {
    g_nativeDetected = true;
    g_nativeAvailable = false;
    IpfwSocket sock;
    if (sock.valid()) {
      // IP_FW_XGET with a small buffer is a read-only probe: it returns
      // the current ruleset size (or ENOMEM if the buffer is too small,
      // but it still proves the socket option is understood by the kernel).
      struct {
        ip_fw3_opheader hdr;
        uint32_t data[64];
      } buf;
      memset(&buf, 0, sizeof(buf));
      socklen_t len = sizeof(buf);
      if (ipfw3Get(sock.fd(), IP_FW_XGET, &buf, &len)) {
        g_nativeAvailable = true;
      } else if (errno == ENOMEM || errno == EINVAL) {
        // ENOMEM means the kernel understood the request but our buffer
        // was too small -- the native API is available.
        // EINVAL can indicate the opcode is recognized but the payload
        // format was wrong -- still means the API exists.
        g_nativeAvailable = true;
      }
      // Any other error (ENOPROTOOPT, ENOSYS, etc.) means the kernel
      // module is not loaded or does not support IP_FW3.
    }
  }
  return g_nativeAvailable;
}

bool available() {
  return useNativeApi();
}

// --- Performance logging helper ---

static bool g_logProgress = false;

void setLogProgress(bool enabled) {
  g_logProgress = enabled;
}

// RAII timer that logs elapsed microseconds at destruction
class PerfTimer {
public:
  PerfTimer(const char *op, bool isNative)
    : op_(op), native_(isNative), active_(g_logProgress),
      start_(std::chrono::steady_clock::now()) {}

  ~PerfTimer() {
    if (active_) {
      auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now() - start_).count();
      std::cerr << "[ipfw perf] " << op_
                << (native_ ? " (native)" : " (shell)")
                << ": " << elapsed << " us" << std::endl;
    }
  }

private:
  const char *op_;
  bool native_;
  bool active_;
  std::chrono::steady_clock::time_point start_;
};

// --- Rule operations ---

// Native add via IP_FW_XADD (complex: requires building ip_fw_rule TLV)
// Falls back to ipfw(8) for complex rule strings since the kernel TLV
// format requires parsing rule text into opcodes.

void addRule(unsigned ruleNum, const std::string &rule) {
  // The native API requires converting text rules into binary opcodes
  // (ipfw_insn structures). Since this is equivalent to reimplementing
  // the ipfw(8) parser, we use the command for rule addition and
  // reserve the native API for simple operations (delete, NAT config).
  PerfTimer timer("addRule", false /*always shell*/);
  std::vector<std::string> argv = {CRATE_PATH_IPFW, "add"};
  if (ruleNum > 0)
    argv.push_back(std::to_string(ruleNum));
  std::istringstream iss(rule);
  std::string token;
  while (iss >> token)
    argv.push_back(token);
  Util::execCommand(argv, "add ipfw rule");
}

void deleteRule(unsigned ruleNum) {
  if (useNativeApi()) {
    PerfTimer timer("deleteRule", true);
    IpfwSocket sock;
    if (sock.valid()) {
      struct {
        ip_fw3_opheader hdr;
        uint32_t rulenum;
      } req;
      memset(&req, 0, sizeof(req));
      req.rulenum = ruleNum;
      if (ipfw3Set(sock.fd(), IP_FW_XDEL, &req, sizeof(req)))
        return;
    }
  }
  // Fallback to shell
  PerfTimer timer("deleteRule", false);
  Util::execCommand({CRATE_PATH_IPFW, "delete", std::to_string(ruleNum)},
    "delete ipfw rule");
}

void deleteRulesInSet(unsigned setNum) {
  if (useNativeApi()) {
    PerfTimer timer("deleteRulesInSet", true);
    IpfwSocket sock;
    if (sock.valid()) {
      struct {
        ip_fw3_opheader hdr;
        uint32_t set;
        uint32_t cmd;
      } req;
      memset(&req, 0, sizeof(req));
      req.set = setNum;
      req.cmd = 1; // delete set
      if (ipfw3Set(sock.fd(), IP_FW_XDEL, &req, sizeof(req)))
        return;
    }
  }
  // Fallback to shell
  PerfTimer timer("deleteRulesInSet", false);
  Util::execCommand({CRATE_PATH_IPFW, "delete", "set", std::to_string(setNum)},
    "delete ipfw rule set");
}

void configureNat(unsigned natInstance, const std::string &natConfig) {
  // NAT configuration requires complex TLV encoding; use command fallback
  PerfTimer timer("configureNat", false /*always shell*/);
  std::vector<std::string> argv = {CRATE_PATH_IPFW, "nat",
                                    std::to_string(natInstance), "config"};
  std::istringstream iss(natConfig);
  std::string token;
  while (iss >> token)
    argv.push_back(token);
  Util::execCommand(argv, "configure ipfw NAT");
}

void deleteNat(unsigned natInstance) {
  PerfTimer timer("deleteNat", false /*always shell*/);
  try {
    Util::execCommand({CRATE_PATH_IPFW, "nat", std::to_string(natInstance), "delete"},
      "delete ipfw NAT");
  } catch (const std::exception &e) {
    WARN("failed to delete ipfw NAT instance " << natInstance << ": " << e.what())
  } catch (...) {
    WARN("failed to delete ipfw NAT instance " << natInstance)
  }
}

}
