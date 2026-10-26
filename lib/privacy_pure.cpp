// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privacy_pure.h"
#include "netaddr_pure.h"

#include <cstdint>
#include <cstring>

namespace PrivacyPure {

namespace {

bool isHex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

std::string lower(std::string s) {
  for (auto &c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
  return s;
}

// --- MD5 (RFC 1321) ---

struct Md5 {
  uint32_t a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
  uint64_t len = 0;
  unsigned char buf[64];
  size_t bufLen = 0;

  static uint32_t rol(uint32_t x, int s) { return (x << s) | (x >> (32 - s)); }

  void block(const unsigned char *p) {
    static const uint32_t K[64] = {
      0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
      0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
      0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
      0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
      0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
      0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
      0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
      0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
    static const int S[64] = {
      7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
      5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
      4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
      6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
      M[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) | ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
    uint32_t A = a, B = b, C = c, D = d;
    for (int i = 0; i < 64; i++) {
      uint32_t F; int g;
      if (i < 16)      { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5*i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D;          g = (3*i + 5) % 16; }
      else             { F = C ^ (B | ~D);       g = (7*i) % 16; }
      uint32_t tmp = D; D = C; C = B;
      B = B + rol(A + F + K[i] + M[g], S[i]);
      A = tmp;
    }
    a += A; b += B; c += C; d += D;
  }

  void update(const unsigned char *p, size_t n) {
    len += n;
    while (n > 0) {
      size_t take = 64 - bufLen; if (take > n) take = n;
      std::memcpy(buf + bufLen, p, take);
      bufLen += take; p += take; n -= take;
      if (bufLen == 64) { block(buf); bufLen = 0; }
    }
  }

  std::string finish() {
    uint64_t bits = len * 8;
    unsigned char pad = 0x80;
    update(&pad, 1);
    unsigned char zero = 0;
    while (bufLen != 56) update(&zero, 1);
    unsigned char lenBytes[8];
    for (int i = 0; i < 8; i++) lenBytes[i] = (unsigned char)(bits >> (8*i));
    update(lenBytes, 8);
    static const char *hx = "0123456789abcdef";
    std::string out;
    for (uint32_t w : {a, b, c, d})
      for (int i = 0; i < 4; i++) {
        unsigned char byte = (unsigned char)(w >> (8*i));
        out += hx[byte >> 4]; out += hx[byte & 15];
      }
    return out;
  }
};

}   // namespace

bool isUuid(const std::string &s) {
  if (s.size() != 36) return false;
  for (size_t i = 0; i < s.size(); i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return false; }
    else if (!isHex(s[i])) return false;
  }
  return true;
}

std::string parseHostid(const std::string &text, Mode &modeOut, std::string &uuidOut) {
  if (text.empty() || text == "host") { modeOut = Mode::Host; uuidOut.clear(); return ""; }
  if (text == "random") { modeOut = Mode::Random; uuidOut.clear(); return ""; }
  if (isUuid(text)) { modeOut = Mode::Fixed; uuidOut = lower(text); return ""; }
  return "privacy/hostid: '" + text + "' is not 'host', 'random' or a UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)";
}

std::string parseHostname(const std::string &text, Mode &modeOut, std::string &nameOut) {
  if (text.empty() || text == "host") { modeOut = Mode::Host; nameOut.clear(); return ""; }
  if (text == "random") { modeOut = Mode::Random; nameOut.clear(); return ""; }
  if (text.size() <= 255 && NetAddrPure::isHostname(text)) { modeOut = Mode::Fixed; nameOut = text; return ""; }
  return "privacy/hostname: '" + text + "' is not 'host', 'random' or a host name";
}

std::string uuidFromHex(const std::string &hex32) {
  if (hex32.size() != 32) return "";
  for (char c : hex32) if (!isHex(c)) return "";
  std::string h = lower(hex32);
  h[12] = '4';                                   // version 4
  static const char *var = "89ab";               // variant 10xx
  int v = h[16] >= 'a' ? h[16] - 'a' + 10 : h[16] - '0';
  h[16] = var[v & 3];
  return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" + h.substr(16, 4) + "-" + h.substr(20, 12);
}

std::string md5Hex(const std::string &data) {
  Md5 m;
  m.update(reinterpret_cast<const unsigned char*>(data.data()), data.size());
  return m.finish();
}

unsigned long hostidFromUuid(const std::string &uuid) {
  // /etc/rc.d/hostid: id=`echo -n $uuid | /sbin/md5`; id="0x${id%${id#????????}}"
  const std::string h = md5Hex(uuid).substr(0, 8);
  unsigned long v = 0;
  for (char c : h) {
    v <<= 4;
    v |= (unsigned long)(c >= 'a' ? c - 'a' + 10 : c - '0');
  }
  return v;
}

std::string randomHostname(const std::string &hex) {
  return "crate-" + lower(hex.substr(0, 8));
}

std::vector<std::string> jailParams(const std::string &uuid) {
  if (uuid.empty()) return {};
  return {"host.hostuuid=" + uuid, "host.hostid=" + std::to_string(hostidFromUuid(uuid))};
}

std::string hostidFileContent(const std::string &uuid) { return uuid + "\n"; }

}
