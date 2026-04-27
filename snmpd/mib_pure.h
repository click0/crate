// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure AgentX wire-protocol encoders extracted from snmpd/mib.cpp so
// they can be unit-tested.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace MibPure {

void encodeUint32(std::vector<uint8_t> &buf, uint32_t val);
void encodeOid(std::vector<uint8_t> &buf, const std::vector<uint32_t> &oid,
               bool include = false);
void encodeOctetString(std::vector<uint8_t> &buf, const std::string &s);

}
