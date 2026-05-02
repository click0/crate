// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "mib_pure.h"

#include <cstring>

namespace MibPure {

// --- Encoders ---

void encodeUint32(std::vector<uint8_t> &buf, uint32_t val) {
  buf.push_back((val >> 24) & 0xFF);
  buf.push_back((val >> 16) & 0xFF);
  buf.push_back((val >> 8) & 0xFF);
  buf.push_back(val & 0xFF);
}

static void encodeUint64(std::vector<uint8_t> &buf, uint64_t val) {
  for (int i = 7; i >= 0; i--)
    buf.push_back((val >> (i * 8)) & 0xFF);
}

void encodeOid(std::vector<uint8_t> &buf, const std::vector<uint32_t> &oid,
               bool include) {
  uint8_t prefix = 0;
  size_t start = 0;
  if (oid.size() >= 5 &&
      oid[0] == 1 && oid[1] == 3 && oid[2] == 6 && oid[3] == 1 && oid[4] <= 255) {
    prefix = (uint8_t)oid[4];
    start = 5;
  }

  uint32_t nSubid = (uint32_t)(oid.size() - start);
  buf.push_back((uint8_t)nSubid);
  buf.push_back(prefix);
  buf.push_back(include ? 1 : 0);
  buf.push_back(0); // reserved
  for (size_t i = start; i < oid.size(); i++)
    encodeUint32(buf, oid[i]);
}

void encodeOctetString(std::vector<uint8_t> &buf, const std::string &s) {
  encodeUint32(buf, (uint32_t)s.size());
  for (char c : s)
    buf.push_back((uint8_t)c);
  while (buf.size() % 4 != 0)
    buf.push_back(0);
}

void encodeHeader(std::vector<uint8_t> &buf, const Header &h) {
  buf.push_back(h.version);
  buf.push_back(h.type);
  buf.push_back(h.flags | 0x10);  // ensure NETWORK_BYTE_ORDER flag
  buf.push_back(0);                // reserved
  encodeUint32(buf, h.sessionId);
  encodeUint32(buf, h.transactionId);
  encodeUint32(buf, h.packetId);
  encodeUint32(buf, h.payloadLen);
}

// --- Decoders ---

namespace {

uint32_t loadU32be(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
       | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}
uint32_t loadU32le(const uint8_t *p) {
  return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[1] <<  8) |  (uint32_t)p[0];
}

} // anon

int decodeHeader(const std::vector<uint8_t> &buf, size_t offset, Header &out) {
  if (buf.size() < offset + 20) return 0;
  const uint8_t *p = buf.data() + offset;
  out.version = p[0];
  out.type    = p[1];
  out.flags   = p[2];
  // NETWORK_BYTE_ORDER bit (0x10): when set the rest is big-endian.
  bool be = (out.flags & 0x10) != 0;
  auto load = be ? loadU32be : loadU32le;
  out.sessionId     = load(p + 4);
  out.transactionId = load(p + 8);
  out.packetId      = load(p + 12);
  out.payloadLen    = load(p + 16);
  return 20;
}

int decodeOid(const std::vector<uint8_t> &buf, size_t offset,
              std::vector<uint32_t> &out, bool *include) {
  if (buf.size() < offset + 4) return 0;
  uint8_t nSubid = buf[offset];
  uint8_t prefix = buf[offset + 1];
  bool inc      = buf[offset + 2] != 0;
  // byte 3 reserved
  size_t bytes = 4 + (size_t)nSubid * 4;
  if (buf.size() < offset + bytes) return 0;

  out.clear();
  if (prefix != 0) {
    out.push_back(1); out.push_back(3); out.push_back(6);
    out.push_back(1); out.push_back(prefix);
  }
  for (size_t i = 0; i < nSubid; i++)
    out.push_back(loadU32be(buf.data() + offset + 4 + i * 4));
  if (include) *include = inc;
  return (int)bytes;
}

int decodeOctetString(const std::vector<uint8_t> &buf, size_t offset,
                      std::string &out) {
  if (buf.size() < offset + 4) return 0;
  uint32_t n = loadU32be(buf.data() + offset);
  size_t padded = ((n + 3) / 4) * 4;
  if (buf.size() < offset + 4 + padded) return 0;
  out.assign((const char *)(buf.data() + offset + 4), n);
  return (int)(4 + padded);
}

int decodeSearchRange(const std::vector<uint8_t> &buf, size_t offset,
                      std::vector<uint32_t> &startOid,
                      std::vector<uint32_t> &endOid,
                      bool *startInclude) {
  size_t pos = offset;
  bool inc = false;
  int n = decodeOid(buf, pos, startOid, &inc);
  if (n <= 0) return 0;
  pos += (size_t)n;
  n = decodeOid(buf, pos, endOid);
  if (n <= 0) return 0;
  pos += (size_t)n;
  if (startInclude) *startInclude = inc;
  return (int)(pos - offset);
}

int decodeGetRequest(const std::vector<uint8_t> &buf, size_t offset,
                     uint8_t flags,
                     std::vector<std::vector<uint32_t>> &out) {
  size_t pos = offset;
  // NON_DEFAULT_CONTEXT bit (0x08): a context octet-string precedes
  // the SearchRangeList.
  if (flags & 0x08) {
    std::string ctx;
    int n = decodeOctetString(buf, pos, ctx);
    if (n <= 0) return 0;
    pos += (size_t)n;
  }
  while (pos < buf.size()) {
    std::vector<uint32_t> startOid, endOid;
    int n = decodeSearchRange(buf, pos, startOid, endOid);
    if (n <= 0) return 0;
    pos += (size_t)n;
    out.push_back(std::move(startOid));
  }
  return (int)(pos - offset);
}

// --- VarBind encoders ---

namespace {

void encodeVarBindHeader(std::vector<uint8_t> &buf, uint16_t type,
                         const std::vector<uint32_t> &oid) {
  buf.push_back((type >> 8) & 0xff);
  buf.push_back(type & 0xff);
  buf.push_back(0); // reserved
  buf.push_back(0); // reserved
  encodeOid(buf, oid);
}

} // anon

void encodeVarBindInteger(std::vector<uint8_t> &buf,
                          const std::vector<uint32_t> &oid, int32_t value) {
  encodeVarBindHeader(buf, VB_INTEGER, oid);
  encodeUint32(buf, (uint32_t)value);
}

void encodeVarBindCounter32(std::vector<uint8_t> &buf,
                            const std::vector<uint32_t> &oid, uint32_t value) {
  encodeVarBindHeader(buf, VB_COUNTER32, oid);
  encodeUint32(buf, value);
}

void encodeVarBindGauge32(std::vector<uint8_t> &buf,
                          const std::vector<uint32_t> &oid, uint32_t value) {
  encodeVarBindHeader(buf, VB_GAUGE32, oid);
  encodeUint32(buf, value);
}

void encodeVarBindTimeTicks(std::vector<uint8_t> &buf,
                            const std::vector<uint32_t> &oid, uint32_t value) {
  encodeVarBindHeader(buf, VB_TIMETICKS, oid);
  encodeUint32(buf, value);
}

void encodeVarBindCounter64(std::vector<uint8_t> &buf,
                            const std::vector<uint32_t> &oid, uint64_t value) {
  encodeVarBindHeader(buf, VB_COUNTER64, oid);
  encodeUint64(buf, value);
}

void encodeVarBindOctetString(std::vector<uint8_t> &buf,
                              const std::vector<uint32_t> &oid,
                              const std::string &s) {
  encodeVarBindHeader(buf, VB_OCTETSTRING, oid);
  encodeOctetString(buf, s);
}

void encodeVarBindOid(std::vector<uint8_t> &buf,
                      const std::vector<uint32_t> &oid,
                      const std::vector<uint32_t> &valueOid) {
  encodeVarBindHeader(buf, VB_OID, oid);
  encodeOid(buf, valueOid);
}

void encodeVarBindNull(std::vector<uint8_t> &buf,
                       const std::vector<uint32_t> &oid) {
  encodeVarBindHeader(buf, VB_NULL, oid);
}

void encodeVarBindEndOfMibView(std::vector<uint8_t> &buf,
                               const std::vector<uint32_t> &oid) {
  encodeVarBindHeader(buf, VB_END_OF_MIB_VIEW, oid);
}

void encodeVarBindNoSuchObject(std::vector<uint8_t> &buf,
                               const std::vector<uint32_t> &oid) {
  encodeVarBindHeader(buf, VB_NO_SUCH_OBJECT, oid);
}

void encodeVarBindNoSuchInstance(std::vector<uint8_t> &buf,
                                 const std::vector<uint32_t> &oid) {
  encodeVarBindHeader(buf, VB_NO_SUCH_INSTANCE, oid);
}

void encodeResponseHeader(std::vector<uint8_t> &buf,
                          uint32_t sysUpTime,
                          uint16_t errorStatus,
                          uint16_t errorIndex) {
  encodeUint32(buf, sysUpTime);
  buf.push_back((errorStatus >> 8) & 0xff);
  buf.push_back(errorStatus & 0xff);
  buf.push_back((errorIndex >> 8) & 0xff);
  buf.push_back(errorIndex & 0xff);
}

// --- OID comparison + walking ---

int compareOid(const std::vector<uint32_t> &a, const std::vector<uint32_t> &b) {
  size_t n = a.size() < b.size() ? a.size() : b.size();
  for (size_t i = 0; i < n; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return  1;
  }
  if (a.size() < b.size()) return -1;
  if (a.size() > b.size()) return  1;
  return 0;
}

bool oidIsChildOf(const std::vector<uint32_t> &oid,
                  const std::vector<uint32_t> &prefix) {
  if (oid.size() <= prefix.size()) return false;
  for (size_t i = 0; i < prefix.size(); i++)
    if (oid[i] != prefix[i]) return false;
  return true;
}

bool oidEquals(const std::vector<uint32_t> &a,
               const std::vector<uint32_t> &b) {
  return a == b;
}

} // namespace MibPure
