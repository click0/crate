// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "mib_pure.h"

namespace MibPure {

void encodeUint32(std::vector<uint8_t> &buf, uint32_t val) {
  buf.push_back((val >> 24) & 0xFF);
  buf.push_back((val >> 16) & 0xFF);
  buf.push_back((val >> 8) & 0xFF);
  buf.push_back(val & 0xFF);
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
  encodeUint32(buf, nSubid);
  buf.push_back(prefix);
  buf.push_back(include ? 1 : 0);
  buf.push_back(0); // reserved
  buf.push_back(0);
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

}
