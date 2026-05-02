// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ws_pure.h"

#include <cstdint>
#include <cstring>
#include <sstream>

namespace WsPure {

// ---------------------------------------------------------------------------
// SHA-1 (RFC 3174). ~80 lines; not the world's most efficient impl, but
// the WebSocket handshake hashes <100 bytes per connection so this is fine.
// ---------------------------------------------------------------------------

namespace {

constexpr uint32_t rotl32(uint32_t v, int n) {
  return (v << n) | (v >> (32 - n));
}

void sha1Block(const uint8_t block[64], uint32_t h[5]) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++) {
    w[i] = (uint32_t)block[i * 4] << 24
         | (uint32_t)block[i * 4 + 1] << 16
         | (uint32_t)block[i * 4 + 2] << 8
         | (uint32_t)block[i * 4 + 3];
  }
  for (int i = 16; i < 80; i++)
    w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20)      { f = (b & c) | ((~b) & d);            k = 0x5A827999; }
    else if (i < 40) { f = b ^ c ^ d;                       k = 0x6ED9EBA1; }
    else if (i < 60) { f = (b & c) | (b & d) | (c & d);     k = 0x8F1BBCDC; }
    else             { f = b ^ c ^ d;                       k = 0xCA62C1D6; }
    uint32_t t = rotl32(a, 5) + f + e + k + w[i];
    e = d; d = c; c = rotl32(b, 30); b = a; a = t;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

} // anon

std::string sha1Raw(const std::string &input) {
  uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
  uint64_t totalBits = (uint64_t)input.size() * 8;

  size_t i = 0;
  uint8_t block[64];
  while (i + 64 <= input.size()) {
    std::memcpy(block, input.data() + i, 64);
    sha1Block(block, h);
    i += 64;
  }
  // Final block(s) with padding.
  size_t rem = input.size() - i;
  std::memcpy(block, input.data() + i, rem);
  block[rem] = 0x80;
  if (rem + 1 > 56) {
    std::memset(block + rem + 1, 0, 64 - rem - 1);
    sha1Block(block, h);
    std::memset(block, 0, 56);
  } else {
    std::memset(block + rem + 1, 0, 56 - rem - 1);
  }
  for (int b = 0; b < 8; b++)
    block[56 + b] = (uint8_t)(totalBits >> ((7 - b) * 8));
  sha1Block(block, h);

  std::string out(20, '\0');
  for (int j = 0; j < 5; j++) {
    out[j * 4]     = (char)((h[j] >> 24) & 0xff);
    out[j * 4 + 1] = (char)((h[j] >> 16) & 0xff);
    out[j * 4 + 2] = (char)((h[j] >>  8) & 0xff);
    out[j * 4 + 3] = (char)( h[j]        & 0xff);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Base64 (RFC 4648, no line breaks).
// ---------------------------------------------------------------------------

std::string base64Encode(const std::string &input) {
  static const char *alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((input.size() + 2) / 3) * 4);
  size_t i = 0;
  while (i + 3 <= input.size()) {
    uint32_t n = ((uint8_t)input[i] << 16)
               | ((uint8_t)input[i + 1] << 8)
               |  (uint8_t)input[i + 2];
    out += alphabet[(n >> 18) & 0x3f];
    out += alphabet[(n >> 12) & 0x3f];
    out += alphabet[(n >>  6) & 0x3f];
    out += alphabet[ n        & 0x3f];
    i += 3;
  }
  if (i < input.size()) {
    uint32_t n = (uint8_t)input[i] << 16;
    if (i + 1 < input.size()) n |= (uint8_t)input[i + 1] << 8;
    out += alphabet[(n >> 18) & 0x3f];
    out += alphabet[(n >> 12) & 0x3f];
    if (i + 1 < input.size()) {
      out += alphabet[(n >> 6) & 0x3f];
      out += '=';
    } else {
      out += "==";
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Handshake.
// ---------------------------------------------------------------------------

std::string computeAcceptKey(const std::string &clientKey) {
  static const std::string GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  return base64Encode(sha1Raw(clientKey + GUID));
}

namespace {

std::string trim(const std::string &s) {
  size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
  while (b > a && (s[b-1] == ' ' || s[b-1] == '\t' || s[b-1] == '\r' || s[b-1] == '\n')) b--;
  return s.substr(a, b - a);
}

std::string toLower(std::string s) {
  for (auto &c : s) if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
  return s;
}

bool ieq(const std::string &a, const std::string &b) {
  return toLower(a) == toLower(b);
}

} // anon

HandshakeRequest parseHandshakeRequest(const std::string &raw) {
  HandshakeRequest r;

  // First line: `GET <path> HTTP/1.1`
  auto firstNl = raw.find("\r\n");
  if (firstNl == std::string::npos) {
    r.failureReason = "missing CRLF after request line";
    return r;
  }
  auto firstLine = raw.substr(0, firstNl);
  auto sp1 = firstLine.find(' ');
  auto sp2 = firstLine.find(' ', sp1 == std::string::npos ? 0 : sp1 + 1);
  if (sp1 == std::string::npos || sp2 == std::string::npos) {
    r.failureReason = "malformed request line";
    return r;
  }
  std::string method = firstLine.substr(0, sp1);
  if (!ieq(method, "GET")) {
    r.failureReason = "method must be GET";
    return r;
  }
  r.path = firstLine.substr(sp1 + 1, sp2 - sp1 - 1);

  // Header parsing.
  bool sawUpgrade = false, sawConnection = false;
  size_t i = firstNl + 2;
  while (i < raw.size()) {
    auto nl = raw.find("\r\n", i);
    if (nl == std::string::npos) break;
    if (nl == i) break; // empty line — end of headers
    auto line = raw.substr(i, nl - i);
    i = nl + 2;
    auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    auto name = trim(line.substr(0, colon));
    auto val  = trim(line.substr(colon + 1));
    auto lname = toLower(name);
    if (lname == "upgrade") {
      if (ieq(val, "websocket")) sawUpgrade = true;
    } else if (lname == "connection") {
      // Connection: keep-alive, Upgrade  — case-insensitive substring match.
      auto lval = toLower(val);
      if (lval.find("upgrade") != std::string::npos) sawConnection = true;
    } else if (lname == "sec-websocket-key") {
      r.clientKey = val;
    } else if (lname == "sec-websocket-version") {
      try { r.version = std::stoi(val); } catch (...) { r.version = 0; }
    }
  }

  if (!sawUpgrade)         { r.failureReason = "missing 'Upgrade: websocket' header";    return r; }
  if (!sawConnection)      { r.failureReason = "missing 'Connection: Upgrade' header";   return r; }
  if (r.clientKey.empty()) { r.failureReason = "missing Sec-WebSocket-Key header";       return r; }
  if (r.version != 13)     { r.failureReason = "unsupported Sec-WebSocket-Version";      return r; }
  r.ok = true;
  return r;
}

std::string buildHandshakeResponse(const std::string &acceptKey) {
  std::ostringstream os;
  os << "HTTP/1.1 101 Switching Protocols\r\n"
     << "Upgrade: websocket\r\n"
     << "Connection: Upgrade\r\n"
     << "Sec-WebSocket-Accept: " << acceptKey << "\r\n"
     << "\r\n";
  return os.str();
}

std::string buildHandshakeRejection(const std::string &reason) {
  std::ostringstream body;
  body << "{\"error\":\"" << reason << "\"}";
  std::ostringstream os;
  os << "HTTP/1.1 400 Bad Request\r\n"
     << "Content-Type: application/json\r\n"
     << "Content-Length: " << body.str().size() << "\r\n"
     << "Connection: close\r\n"
     << "\r\n"
     << body.str();
  return os.str();
}

// ---------------------------------------------------------------------------
// Frame parser / encoder.
// ---------------------------------------------------------------------------

int parseFrame(const std::string &buf, Frame &out) {
  if (buf.size() < 2) return 0;
  uint8_t b0 = (uint8_t)buf[0];
  uint8_t b1 = (uint8_t)buf[1];

  bool fin = (b0 & 0x80) != 0;
  uint8_t op = b0 & 0x0f;
  bool masked = (b1 & 0x80) != 0;
  uint64_t len = b1 & 0x7f;

  // Reject reserved opcodes early.
  switch (op) {
    case 0x0: case 0x1: case 0x2:
    case 0x8: case 0x9: case 0xA:
      break;
    default: return -1;
  }
  // Control frames must be FIN and ≤125 bytes (RFC 6455 §5.5).
  bool isControl = (op & 0x8) != 0;
  if (isControl && (!fin || len > 125)) return -1;

  size_t pos = 2;
  if (len == 126) {
    if (buf.size() < pos + 2) return 0;
    len = ((uint8_t)buf[pos] << 8) | (uint8_t)buf[pos + 1];
    pos += 2;
  } else if (len == 127) {
    if (buf.size() < pos + 8) return 0;
    len = 0;
    for (int k = 0; k < 8; k++) len = (len << 8) | (uint8_t)buf[pos + k];
    pos += 8;
    if (len & (1ULL << 63)) return -1; // MSB must be 0
  }

  uint8_t maskKey[4] = {0, 0, 0, 0};
  if (masked) {
    if (buf.size() < pos + 4) return 0;
    for (int k = 0; k < 4; k++) maskKey[k] = (uint8_t)buf[pos + k];
    pos += 4;
  }

  if (buf.size() < pos + len) return 0;

  out.fin = fin;
  out.masked = masked;
  out.opcode = static_cast<Opcode>(op);
  out.payload.assign(len, '\0');
  for (uint64_t k = 0; k < len; k++) {
    uint8_t b = (uint8_t)buf[pos + k];
    if (masked) b ^= maskKey[k % 4];
    out.payload[k] = (char)b;
  }
  return (int)(pos + len);
}

std::string encodeFrame(Opcode opcode, const std::string &payload,
                        bool mask, const std::string &maskKey) {
  std::string out;
  out.reserve(payload.size() + 14);
  uint8_t b0 = 0x80 | (uint8_t)opcode;     // FIN=1
  out += (char)b0;

  uint64_t len = payload.size();
  uint8_t maskBit = mask ? 0x80 : 0x00;
  if (len <= 125) {
    out += (char)(maskBit | (uint8_t)len);
  } else if (len <= 0xffff) {
    out += (char)(maskBit | 126);
    out += (char)((len >> 8) & 0xff);
    out += (char)( len       & 0xff);
  } else {
    out += (char)(maskBit | 127);
    for (int k = 7; k >= 0; k--)
      out += (char)((len >> (k * 8)) & 0xff);
  }

  uint8_t key[4] = {0, 0, 0, 0};
  if (mask) {
    for (int k = 0; k < 4; k++) {
      key[k] = (k < (int)maskKey.size()) ? (uint8_t)maskKey[k] : 0;
      out += (char)key[k];
    }
  }
  for (size_t k = 0; k < payload.size(); k++) {
    uint8_t b = (uint8_t)payload[k];
    if (mask) b ^= key[k % 4];
    out += (char)b;
  }
  return out;
}

std::string encodeCloseFrame(uint16_t code, const std::string &reason) {
  std::string payload;
  payload += (char)((code >> 8) & 0xff);
  payload += (char)( code       & 0xff);
  payload += reason;
  return encodeFrame(Opcode::Close, payload);
}

} // namespace WsPure
