// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure AgentX wire-protocol helpers (RFC 2741). Encoders + decoders +
// varBind builders. No I/O — all unit-testable on Linux without
// connecting to a master agent.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace MibPure {

// --- AgentX header ---

struct Header {
  uint8_t version  = 1;
  uint8_t type     = 0;     // PDU type, see PduType below
  uint8_t flags    = 0;     // bit 4 (0x10) = NETWORK_BYTE_ORDER
  uint32_t sessionId    = 0;
  uint32_t transactionId = 0;
  uint32_t packetId     = 0;
  uint32_t payloadLen   = 0;
};

// PDU types we care about. RFC 2741 §6.1.
enum PduType : uint8_t {
  PDU_OPEN     = 1,
  PDU_CLOSE    = 2,
  PDU_REGISTER = 3,
  PDU_GET      = 6,
  PDU_GETNEXT  = 7,
  PDU_GETBULK  = 8,
  PDU_NOTIFY   = 12,
  PDU_RESPONSE = 18,
};

// AgentX VarBind value tags (RFC 2741 §5.4).
enum VarBindType : uint16_t {
  VB_INTEGER     = 2,
  VB_OCTETSTRING = 4,
  VB_NULL        = 5,
  VB_OID         = 6,
  VB_COUNTER32   = 65,
  VB_GAUGE32     = 66,
  VB_TIMETICKS   = 67,
  VB_OPAQUE      = 68,
  VB_COUNTER64   = 70,
  VB_NO_SUCH_OBJECT   = 128,
  VB_NO_SUCH_INSTANCE = 129,
  VB_END_OF_MIB_VIEW  = 130,
};

// Common AgentX error statuses we surface in responses.
enum ErrorStatus : uint16_t {
  ERR_NO_ERROR = 0,
  ERR_GENERIC  = 5,
  ERR_NO_ACCESS    = 6,
  ERR_WRONG_TYPE   = 7,
};

// --- Encoders (already used by mib.cpp; kept stable) ---

void encodeUint32(std::vector<uint8_t> &buf, uint32_t val);
void encodeOid(std::vector<uint8_t> &buf, const std::vector<uint32_t> &oid,
               bool include = false);
void encodeOctetString(std::vector<uint8_t> &buf, const std::string &s);

// Build a 20-byte AgentX header. NETWORK_BYTE_ORDER flag is set; all
// other flags clear. Caller must already know the payload length.
void encodeHeader(std::vector<uint8_t> &buf, const Header &h);

// --- Decoders ---

// Parse a 20-byte AgentX header from `buf` starting at `offset`.
// Returns the number of bytes consumed (20) on success or 0 on
// short input. Honours the NETWORK_BYTE_ORDER flag — flips endian
// when the bit is clear (some older masters send little-endian).
int decodeHeader(const std::vector<uint8_t> &buf, size_t offset, Header &out);

// Parse an AgentX OID at `offset`. Returns the number of bytes
// consumed or 0 on short/invalid input. `include` reports the I-bit
// (used by SearchRanges).
int decodeOid(const std::vector<uint8_t> &buf, size_t offset,
              std::vector<uint32_t> &out, bool *include = nullptr);

// Parse an AgentX OctetString. Honours 4-byte zero padding.
int decodeOctetString(const std::vector<uint8_t> &buf, size_t offset,
                      std::string &out);

// Parse a SearchRange (OID, OID). Returns bytes consumed.
int decodeSearchRange(const std::vector<uint8_t> &buf, size_t offset,
                      std::vector<uint32_t> &startOid,
                      std::vector<uint32_t> &endOid,
                      bool *startInclude = nullptr);

// Parse a Get/GetNext payload — a sequence of SearchRanges with an
// optional context octet-string prefix (skipped if NON_DEFAULT_CONTEXT
// flag set on the header). Each parsed start-OID is appended to `out`.
// `flags` is the header's flags byte.
int decodeGetRequest(const std::vector<uint8_t> &buf, size_t offset,
                     uint8_t flags,
                     std::vector<std::vector<uint32_t>> &out);

// --- VarBind encoders ---

// Encode a single VarBind: type(2) + reserved(2) + OID + value.
void encodeVarBindInteger(std::vector<uint8_t> &buf,
                          const std::vector<uint32_t> &oid, int32_t value);
void encodeVarBindCounter32(std::vector<uint8_t> &buf,
                            const std::vector<uint32_t> &oid, uint32_t value);
void encodeVarBindGauge32(std::vector<uint8_t> &buf,
                          const std::vector<uint32_t> &oid, uint32_t value);
void encodeVarBindTimeTicks(std::vector<uint8_t> &buf,
                            const std::vector<uint32_t> &oid, uint32_t value);
void encodeVarBindCounter64(std::vector<uint8_t> &buf,
                            const std::vector<uint32_t> &oid, uint64_t value);
void encodeVarBindOctetString(std::vector<uint8_t> &buf,
                              const std::vector<uint32_t> &oid,
                              const std::string &s);
void encodeVarBindOid(std::vector<uint8_t> &buf,
                      const std::vector<uint32_t> &oid,
                      const std::vector<uint32_t> &valueOid);
void encodeVarBindNull(std::vector<uint8_t> &buf,
                       const std::vector<uint32_t> &oid);
// Exception VarBinds for GetNext walk-off-end / no-such-instance:
void encodeVarBindEndOfMibView(std::vector<uint8_t> &buf,
                               const std::vector<uint32_t> &oid);
void encodeVarBindNoSuchObject(std::vector<uint8_t> &buf,
                               const std::vector<uint32_t> &oid);
void encodeVarBindNoSuchInstance(std::vector<uint8_t> &buf,
                                 const std::vector<uint32_t> &oid);

// Build the Response payload prefix: sysUpTime(4) + errorStatus(2)
// + errorIndex(2). Caller appends VarBind list afterwards.
void encodeResponseHeader(std::vector<uint8_t> &buf,
                          uint32_t sysUpTime,
                          uint16_t errorStatus,
                          uint16_t errorIndex);

// --- OID comparison + walking helpers ---

// strcmp-style comparison for OIDs: -1 / 0 / +1.
int compareOid(const std::vector<uint32_t> &a, const std::vector<uint32_t> &b);

// True iff `oid` is a strict child of `prefix` (i.e. starts with
// `prefix` and is longer).
bool oidIsChildOf(const std::vector<uint32_t> &oid,
                  const std::vector<uint32_t> &prefix);

// True iff `oid == prefix` exactly.
bool oidEquals(const std::vector<uint32_t> &a,
               const std::vector<uint32_t> &b);

} // namespace MibPure
