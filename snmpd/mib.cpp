// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// SNMP MIB implementation — AgentX subagent for CRATE-MIB.
//
// OID base: enterprises.59999 (placeholder private enterprise number)
// NOTE: PEN 59999 is a placeholder. A real PEN must be registered with IANA
// at https://www.iana.org/assignments/enterprise-numbers/ before production use.
//
// Uses bsnmpd AgentX on FreeBSD, or net-snmp AgentX as fallback.
//
// Implements the AgentX wire protocol (RFC 2741) for communicating
// with a master SNMP agent (bsnmpd or snmpd).
//
// MIB tree structure:
//   .1.3.6.1.4.1.59999           — CRATE-MIB root
//   .1.3.6.1.4.1.59999.1         — crateSystem (scalars)
//   .1.3.6.1.4.1.59999.1.1.0     — crateContainerTotal   (Integer32) total containers
//   .1.3.6.1.4.1.59999.1.2.0     — crateContainerRunning (Integer32) running containers
//   .1.3.6.1.4.1.59999.1.3.0     — crateVersion          (OctetString)
//   .1.3.6.1.4.1.59999.1.4.0     — crateHostname         (OctetString)
//   .1.3.6.1.4.1.59999.2         — crateContainers (table)
//   .1.3.6.1.4.1.59999.2.1       — crateContainerTable   (SEQUENCE OF CrateContainerEntry)
//   .1.3.6.1.4.1.59999.2.1.1.X   — crateContainerEntry
//     .2.1.1.1.X — crateContainerIndex  (Integer32) row index
//     .2.1.1.2.X — crateContainerName   (OctetString)
//     .2.1.1.3.X — crateContainerJid    (Integer32)
//     .2.1.1.4.X — crateContainerState  (Integer32) 0=stopped,1=running,2=starting,3=dying
//     .2.1.1.5.X — crateContainerCpu    (Integer32) CPU% × 100
//     .2.1.1.6.X — crateContainerMemKB  (Counter64) RSS in KB
//     .2.1.1.7.X — crateContainerNetRx  (Counter64) bytes received
//     .2.1.1.8.X — crateContainerNetTx  (Counter64) bytes transmitted
//     .2.1.1.9.X — crateContainerUptime (TimeTicks) hundredths of a second

#include "mib.h"
#include "mib_pure.h"
#include "collector.h"

#include "util.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <cstdint>
#include <mutex>
#include <iostream>
#include <vector>

namespace CrateSnmp {

// --- AgentX protocol constants (RFC 2741) ---

static constexpr uint8_t AGENTX_VERSION = 1;

// PDU types
static constexpr uint8_t AGENTX_OPEN_PDU      = 1;
static constexpr uint8_t AGENTX_CLOSE_PDU     = 2;
static constexpr uint8_t AGENTX_REGISTER_PDU  = 3;
static constexpr uint8_t AGENTX_RESPONSE_PDU  = 18;

// Error status
static constexpr uint16_t AGENTX_NO_ERROR = 0;

// OID: .1.3.6.1.4.1.59999 (enterprises.59999 — placeholder PEN)
// NOTE: Replace 59999 with the actual IANA-assigned PEN before production deployment.
static const std::vector<uint32_t> CRATE_BASE_OID = {1, 3, 6, 1, 4, 1, 59999};

// Scalar OIDs under crateSystem (.1.3.6.1.4.1.59999.1)
static const std::vector<uint32_t> OID_CONTAINER_TOTAL   = {1, 3, 6, 1, 4, 1, 59999, 1, 1, 0};
static const std::vector<uint32_t> OID_CONTAINER_RUNNING = {1, 3, 6, 1, 4, 1, 59999, 1, 2, 0};
static const std::vector<uint32_t> OID_VERSION           = {1, 3, 6, 1, 4, 1, 59999, 1, 3, 0};
static const std::vector<uint32_t> OID_HOSTNAME          = {1, 3, 6, 1, 4, 1, 59999, 1, 4, 0};

// Container table OID: .1.3.6.1.4.1.59999.2.1
static const std::vector<uint32_t> OID_CONTAINER_TABLE   = {1, 3, 6, 1, 4, 1, 59999, 2, 1};

// --- AgentX connection state ---

static int g_agentxFd = -1;
static uint32_t g_sessionId = 0;
static uint32_t g_transactionId = 0;

// Cached MIB data (updated by collector, read by AgentX handler)
static std::mutex g_mibMutex;
static std::vector<ContainerMetrics> g_containers;
static unsigned g_totalCount = 0;
static unsigned g_runningCount = 0;
static std::string g_version = "0.6.7";
static std::string g_hostname;

// --- AgentX PDU helpers ---

// Encode a 4-byte network-order integer (forward to MibPure)
static inline void encodeUint32(std::vector<uint8_t> &buf, uint32_t val) {
  MibPure::encodeUint32(buf, val);
}

// Encode AgentX header (20 bytes) — thin wrapper over MibPure.
static void encodeHeader(std::vector<uint8_t> &buf, uint8_t type,
                          uint32_t sessionId, uint32_t transId,
                          uint32_t payloadLen) {
  MibPure::Header h;
  h.version  = AGENTX_VERSION;
  h.type     = type;
  h.sessionId = sessionId;
  h.transactionId = transId;
  h.packetId = transId;       // reuse: simple subagent does no batching
  h.payloadLen = payloadLen;
  MibPure::encodeHeader(buf, h);
}

// Encode an OID in AgentX format (forward to MibPure)
static inline void encodeOid(std::vector<uint8_t> &buf, const std::vector<uint32_t> &oid,
                              bool include = false) {
  MibPure::encodeOid(buf, oid, include);
}

// Encode an Octet String (forward to MibPure)
static inline void encodeOctetString(std::vector<uint8_t> &buf, const std::string &s) {
  MibPure::encodeOctetString(buf, s);
}

// Send a PDU over the AgentX connection
static bool sendPdu(const std::vector<uint8_t> &pdu) {
  if (g_agentxFd < 0)
    return false;
  ssize_t n = ::write(g_agentxFd, pdu.data(), pdu.size());
  return n == (ssize_t)pdu.size();
}

// Read a response PDU (simplified: just read header + check error status)
static bool readResponse() {
  if (g_agentxFd < 0)
    return false;

  uint8_t hdr[20];
  ssize_t n = ::read(g_agentxFd, hdr, sizeof(hdr));
  if (n < 20)
    return false;

  // Check it's a Response PDU
  if (hdr[1] != AGENTX_RESPONSE_PDU)
    return false;

  // Read payload length and skip payload
  uint32_t payloadLen = ((uint32_t)hdr[16] << 24) | ((uint32_t)hdr[17] << 16) |
                        ((uint32_t)hdr[18] << 8) | hdr[19];
  if (payloadLen > 0) {
    std::vector<uint8_t> payload(payloadLen);
    ::read(g_agentxFd, payload.data(), payloadLen);
    // Response payload starts with: sysUpTime(4), error(2), index(2)
    if (payloadLen >= 8) {
      uint16_t errorStatus = ((uint16_t)payload[4] << 8) | payload[5];
      if (errorStatus != AGENTX_NO_ERROR)
        return false;
    }
  }

  return true;
}

// --- Public API ---

bool initAgentX(const std::string &socketPath) {
  try {
    g_hostname = Util::getSysctlString("kern.hostname");
  } catch (...) {
    g_hostname = "unknown";
  }

  // Connect to master agent via Unix socket
  g_agentxFd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (g_agentxFd < 0) {
    std::cerr << "crate-snmpd: failed to create AgentX socket" << std::endl;
    return false;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

  if (::connect(g_agentxFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    std::cerr << "crate-snmpd: failed to connect to AgentX master at "
              << socketPath << ": " << strerror(errno) << std::endl;
    ::close(g_agentxFd);
    g_agentxFd = -1;
    return false;
  }

  // Send Open PDU
  std::vector<uint8_t> payload;
  payload.push_back(5);  // timeout (5 seconds)
  payload.push_back(0); payload.push_back(0); payload.push_back(0); // reserved

  // Subagent OID (our base OID)
  encodeOid(payload, CRATE_BASE_OID);
  // Description
  encodeOctetString(payload, "crate container manager SNMP subagent");

  std::vector<uint8_t> pdu;
  encodeHeader(pdu, AGENTX_OPEN_PDU, 0, ++g_transactionId, (uint32_t)payload.size());
  pdu.insert(pdu.end(), payload.begin(), payload.end());

  if (!sendPdu(pdu)) {
    std::cerr << "crate-snmpd: failed to send Open PDU" << std::endl;
    ::close(g_agentxFd);
    g_agentxFd = -1;
    return false;
  }

  if (!readResponse()) {
    std::cerr << "crate-snmpd: Open PDU rejected by master agent" << std::endl;
    ::close(g_agentxFd);
    g_agentxFd = -1;
    return false;
  }

  // Extract sessionId from response (stored in header bytes 4-7)
  // For simplicity, use transaction ID as session placeholder
  g_sessionId = g_transactionId;

  std::cerr << "crate-snmpd: AgentX connection established (session "
            << g_sessionId << "), PEN .1.3.6.1.4.1.59999" << std::endl;
  return true;
}

// Helper: register a single OID subtree via AgentX Register PDU
static bool registerSubtree(const std::vector<uint32_t> &oid, const std::string &desc) {
  if (g_agentxFd < 0)
    return false;

  std::vector<uint8_t> payload;

  // Context (empty)
  encodeUint32(payload, 0);

  // Timeout, priority, range_subid
  payload.push_back(5);   // timeout
  payload.push_back(127); // priority (default)
  payload.push_back(0);   // range_subid
  payload.push_back(0);   // reserved

  // Subtree OID
  encodeOid(payload, oid);

  std::vector<uint8_t> pdu;
  encodeHeader(pdu, AGENTX_REGISTER_PDU, g_sessionId,
               ++g_transactionId, (uint32_t)payload.size());
  pdu.insert(pdu.end(), payload.begin(), payload.end());

  if (!sendPdu(pdu) || !readResponse()) {
    std::cerr << "crate-snmpd: failed to register " << desc << std::endl;
    return false;
  }

  std::cerr << "crate-snmpd: registered " << desc << std::endl;
  return true;
}

void registerMib() {
  if (g_agentxFd < 0)
    return;

  // Register the entire CRATE-MIB subtree under enterprises.59999
  // This covers:
  //   .1.3.6.1.4.1.59999.1     — crateSystem (scalars)
  //   .1.3.6.1.4.1.59999.1.1.0 — crateContainerTotal   (Integer32)
  //   .1.3.6.1.4.1.59999.1.2.0 — crateContainerRunning (Integer32)
  //   .1.3.6.1.4.1.59999.1.3.0 — crateVersion          (OctetString)
  //   .1.3.6.1.4.1.59999.1.4.0 — crateHostname         (OctetString)
  //   .1.3.6.1.4.1.59999.2.1   — crateContainerTable   (SEQUENCE OF CrateContainerEntry)
  //   .1.3.6.1.4.1.59999.2.1.1.{1-9}.X — per-container columns

  // Register the root subtree (covers all children)
  registerSubtree(CRATE_BASE_OID, "CRATE-MIB root at .1.3.6.1.4.1.59999");

  // Also register specific subtrees for finer-grained control:
  // Scalars: .1.3.6.1.4.1.59999.1 (crateSystem)
  auto systemOid = CRATE_BASE_OID;
  systemOid.push_back(1);
  registerSubtree(systemOid, "crateSystem at .1.3.6.1.4.1.59999.1");

  // Container table: .1.3.6.1.4.1.59999.2.1 (crateContainerTable)
  registerSubtree(OID_CONTAINER_TABLE, "crateContainerTable at .1.3.6.1.4.1.59999.2.1");

  std::cerr << "crate-snmpd: MIB registration complete — PEN 59999 (placeholder)" << std::endl;
  std::cerr << "crate-snmpd: NOTE: register a real PEN with IANA before production use"
            << std::endl;
}

void updateMibData(const Collector &collector) {
  std::lock_guard<std::mutex> lock(g_mibMutex);
  g_containers = collector.containers();
  g_totalCount = collector.totalCount();
  g_runningCount = collector.runningCount();
}

void sendTrap(TrapType type, const std::string &containerName, int jid) {
  const char *typeName = "unknown";
  switch (type) {
  case TrapType::ContainerStarted: typeName = "started"; break;
  case TrapType::ContainerStopped: typeName = "stopped"; break;
  case TrapType::ContainerOOM:     typeName = "oom";     break;
  }

  // Log the event regardless of AgentX connection status
  std::cerr << "crate-snmpd: trap " << typeName
            << " container=" << containerName << " jid=" << jid << std::endl;

  if (g_agentxFd < 0)
    return;

  // AgentX Notify PDU would go here
  // For now, the trap is logged but not sent over SNMP
  // Full implementation requires encoding VarBindList with:
  //   sysUpTime.0, snmpTrapOID.0, and trap-specific varbinds
}

// --- AgentX resolver: look up an OID in our MIB and append the
//     appropriate VarBind (or exception) to `out`. ---

namespace {

// All supported scalar OIDs in lexicographic order so GetNext walks
// produce the right next-OID. Values come from the cached g_*
// state under g_mibMutex.
struct ScalarOid {
  std::vector<uint32_t> oid;
  uint16_t type;     // VarBind type tag (Integer32 / OctetString)
};

// Scalars under .1.3.6.1.4.1.59999.1.*
const std::vector<ScalarOid> &scalarTable() {
  static const std::vector<ScalarOid> t = {
    {{1, 3, 6, 1, 4, 1, 59999, 1, 1, 0}, MibPure::VB_INTEGER},
    {{1, 3, 6, 1, 4, 1, 59999, 1, 2, 0}, MibPure::VB_INTEGER},
    {{1, 3, 6, 1, 4, 1, 59999, 1, 3, 0}, MibPure::VB_OCTETSTRING},
    {{1, 3, 6, 1, 4, 1, 59999, 1, 4, 0}, MibPure::VB_OCTETSTRING},
  };
  return t;
}

// Append the value of a known scalar OID to `out` as a VarBind.
// Caller already holds g_mibMutex.
void encodeScalarValue(std::vector<uint8_t> &out, const ScalarOid &s) {
  if (s.oid.size() == 10 && s.oid[7] == 1 && s.oid[8] == 1) {
    MibPure::encodeVarBindInteger(out, s.oid, (int32_t)g_totalCount);
  } else if (s.oid.size() == 10 && s.oid[7] == 1 && s.oid[8] == 2) {
    MibPure::encodeVarBindInteger(out, s.oid, (int32_t)g_runningCount);
  } else if (s.oid.size() == 10 && s.oid[7] == 1 && s.oid[8] == 3) {
    MibPure::encodeVarBindOctetString(out, s.oid, g_version);
  } else if (s.oid.size() == 10 && s.oid[7] == 1 && s.oid[8] == 4) {
    MibPure::encodeVarBindOctetString(out, s.oid, g_hostname);
  } else {
    MibPure::encodeVarBindNoSuchObject(out, s.oid);
  }
}

// --- Get-resolver: exact-match lookup. ---
void resolveGet(const std::vector<uint32_t> &oid, std::vector<uint8_t> &out) {
  std::lock_guard<std::mutex> lock(g_mibMutex);
  for (auto &s : scalarTable()) {
    if (MibPure::oidEquals(oid, s.oid)) {
      encodeScalarValue(out, s);
      return;
    }
  }
  // Container table is not yet exposed through Get/GetNext (would need
  // per-row resolution). Reply with noSuchInstance for table queries
  // so the master agent reports the gap cleanly to the SNMP client.
  MibPure::encodeVarBindNoSuchInstance(out, oid);
}

// --- GetNext-resolver: lexicographic next OID. ---
void resolveGetNext(const std::vector<uint32_t> &oid, std::vector<uint8_t> &out) {
  std::lock_guard<std::mutex> lock(g_mibMutex);
  for (auto &s : scalarTable()) {
    if (MibPure::compareOid(s.oid, oid) > 0) {
      encodeScalarValue(out, s);
      return;
    }
  }
  // Walked off the end of our subtree.
  MibPure::encodeVarBindEndOfMibView(out, oid);
}

// --- Read up to `n` bytes from g_agentxFd. Returns -1 on error. ---
ssize_t readN(int fd, void *buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t r = ::read(fd, (char*)buf + off, n - off);
    if (r <= 0) return r < 0 ? -1 : (ssize_t)off;
    off += (size_t)r;
  }
  return (ssize_t)n;
}

} // anon

bool dispatchOnce(int timeoutMs) {
  if (g_agentxFd < 0) return false;

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(g_agentxFd, &rfds);
  timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
  int sel = ::select(g_agentxFd + 1, &rfds, nullptr, nullptr, &tv);
  if (sel <= 0) return false;

  uint8_t hdrBytes[20];
  if (readN(g_agentxFd, hdrBytes, 20) != 20) return false;

  std::vector<uint8_t> hdrVec(hdrBytes, hdrBytes + 20);
  MibPure::Header h;
  if (MibPure::decodeHeader(hdrVec, 0, h) != 20) return false;

  std::vector<uint8_t> payload(h.payloadLen);
  if (h.payloadLen > 0 && readN(g_agentxFd, payload.data(), h.payloadLen) != (ssize_t)h.payloadLen)
    return false;

  // Only Get and GetNext are handled; everything else is acknowledged
  // with an empty Response so the master agent doesn't stall.
  std::vector<uint8_t> respPayload;
  MibPure::encodeResponseHeader(respPayload, /*sysUpTime*/0,
                                MibPure::ERR_NO_ERROR, 0);

  if (h.type == MibPure::PDU_GET || h.type == MibPure::PDU_GETNEXT) {
    std::vector<std::vector<uint32_t>> oids;
    MibPure::decodeGetRequest(payload, 0, h.flags, oids);
    for (auto &oid : oids) {
      if (h.type == MibPure::PDU_GET) resolveGet(oid, respPayload);
      else                            resolveGetNext(oid, respPayload);
    }
  }

  std::vector<uint8_t> respPdu;
  MibPure::Header rh;
  rh.version = AGENTX_VERSION;
  rh.type = MibPure::PDU_RESPONSE;
  rh.sessionId = h.sessionId;
  rh.transactionId = h.transactionId;
  rh.packetId = h.packetId;
  rh.payloadLen = (uint32_t)respPayload.size();
  MibPure::encodeHeader(respPdu, rh);
  respPdu.insert(respPdu.end(), respPayload.begin(), respPayload.end());
  ::write(g_agentxFd, respPdu.data(), respPdu.size());
  return true;
}

void shutdownAgentX() {
  if (g_agentxFd < 0)
    return;

  // Send Close PDU
  std::vector<uint8_t> payload;
  payload.push_back(1); // reason: shutdown
  payload.push_back(0); payload.push_back(0); payload.push_back(0);

  std::vector<uint8_t> pdu;
  encodeHeader(pdu, AGENTX_CLOSE_PDU, g_sessionId,
               ++g_transactionId, (uint32_t)payload.size());
  pdu.insert(pdu.end(), payload.begin(), payload.end());

  sendPdu(pdu);
  // Don't wait for response on shutdown

  ::close(g_agentxFd);
  g_agentxFd = -1;
  g_sessionId = 0;

  std::cerr << "crate-snmpd: AgentX session closed" << std::endl;
}

}
