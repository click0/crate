// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "transfer_pure.h"

#include <cstdio>
#include <sstream>

namespace TransferPure {

std::string validateArtifactName(const std::string &name) {
  if (name.empty()) return "artifact name is empty";
  if (name.size() > 128) return "artifact name is longer than 128 chars";
  if (name == "." || name == "..") return "artifact name is reserved";
  for (auto c : name) {
    bool ok = (c >= 'a' && c <= 'z')
           || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9')
           || c == '.' || c == '_' || c == '-';
    if (!ok) {
      std::ostringstream os;
      // Render whitespace and '/' clearly in the error.
      if (c == ' ')       os << "invalid space character in artifact name";
      else if (c == '/')  os << "invalid '/' in artifact name (no path traversal)";
      else                os << "invalid character '" << c << "' in artifact name";
      return os.str();
    }
  }
  return "";
}

std::string formatExportResponse(const std::string &file,
                                 uint64_t sizeBytes,
                                 const std::string &sha256Hex) {
  std::ostringstream os;
  os << "{\"file\":\"" << file << "\""
     << ",\"size\":" << sizeBytes
     << ",\"sha256\":\"" << sha256Hex << "\"}";
  return os.str();
}

std::string formatImportResponse(const std::string &file,
                                 uint64_t sizeBytes,
                                 const std::string &sha256Hex) {
  std::ostringstream os;
  os << "{\"file\":\"" << file << "\""
     << ",\"size\":" << sizeBytes
     << ",\"sha256\":\"" << sha256Hex << "\"}";
  return os.str();
}

const char *sniffArchiveType(const std::string &leading) {
  // xz stream signature: FD 37 7A 58 5A 00
  if (leading.size() >= 6 &&
      (uint8_t)leading[0] == 0xFD &&
      (uint8_t)leading[1] == 0x37 &&
      (uint8_t)leading[2] == 0x7A &&
      (uint8_t)leading[3] == 0x58 &&
      (uint8_t)leading[4] == 0x5A &&
      (uint8_t)leading[5] == 0x00)
    return "xz";
  // openssl enc -salt → "Salted__" then 8 bytes of salt
  if (leading.size() >= 8 && leading.compare(0, 8, "Salted__") == 0)
    return "encrypted";
  return "unknown";
}

std::string hexEncode(const std::string &raw) {
  static const char *d = "0123456789abcdef";
  std::string out;
  out.reserve(raw.size() * 2);
  for (unsigned char c : raw) {
    out += d[(c >> 4) & 0xf];
    out += d[c & 0xf];
  }
  return out;
}

} // namespace TransferPure
