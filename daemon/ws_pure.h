// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for the crated WebSocket console (RFC 6455).
//
// Everything in this header is allocation-light and side-effect-free
// so it can be unit-tested on Linux without any OpenSSL or socket
// plumbing. The runtime side (daemon/ws_console.cpp) handles the TCP
// listener, accept loop, and jail-side I/O.
//

#include <cstdint>
#include <string>
#include <vector>

namespace WsPure {

// --- Hash + base64 (used by the handshake) ---

// Raw SHA-1 digest of `input`. Returns 20 bytes. Implemented inline
// (RFC 3174) so tests do not need to link against libcrypto.
std::string sha1Raw(const std::string &input);

// Standard base64 encoder (RFC 4648, no line breaks). The result
// length is `4 * ceil(input.size() / 3)`. No padding stripping.
std::string base64Encode(const std::string &input);

// --- Handshake ---

// Compute the Sec-WebSocket-Accept header value from the client's
// Sec-WebSocket-Key, per RFC 6455 §4.2.2:
//
//   accept = base64(SHA1(key || "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
std::string computeAcceptKey(const std::string &clientKey);

// Result of parsing a client handshake request.
struct HandshakeRequest {
  bool ok = false;            // overall: all required headers present + valid
  std::string failureReason;  // when !ok: human-readable cause for HTTP 400
  std::string clientKey;      // Sec-WebSocket-Key (base64 16-byte nonce)
  int version = 0;            // Sec-WebSocket-Version (must be 13)
  std::string path;           // request-target
};

// Parse the raw HTTP/1.1 request bytes (header block, ending in
// \r\n\r\n) the daemon read from the socket. Tolerates lower- and
// mixed-case header names, multiple spaces around the colon, and
// extra trailing whitespace. Does NOT validate the host header.
HandshakeRequest parseHandshakeRequest(const std::string &rawRequest);

// Build the 101 Switching Protocols response for an accepted
// handshake. Output ends with \r\n\r\n so it is ready to write to
// the socket.
std::string buildHandshakeResponse(const std::string &acceptKey);

// Build a 400 Bad Request response for a rejected handshake. The
// `reason` is included as the response body so a curl-style client
// can see what went wrong.
std::string buildHandshakeRejection(const std::string &reason);

// --- Frames (RFC 6455 §5) ---

// Subset of the opcodes we care about. Reserved opcodes are
// rejected at parse time.
enum class Opcode : uint8_t {
  Continuation = 0x0,
  Text         = 0x1,
  Binary       = 0x2,
  Close        = 0x8,
  Ping         = 0x9,
  Pong         = 0xA,
};

struct Frame {
  Opcode opcode = Opcode::Text;
  bool fin = true;
  bool masked = false;
  std::string payload; // already unmasked
};

// Parse one frame from a byte buffer. Returns:
//   >0 — number of bytes consumed; `out` filled in.
//    0 — incomplete; caller must read more bytes and try again.
//   <0 — protocol error; close the connection with code 1002.
//
// Per RFC 6455, frames from the client MUST be masked; frames from
// the server MUST NOT be masked. This parser accepts either (it is
// used on both ends) and reports the masked bit in `out.masked`.
int parseFrame(const std::string &buf, Frame &out);

// Build one outgoing frame. `mask` controls the MASK bit:
//   - server -> client: pass mask=false (server frames must not be masked)
//   - client -> server: pass mask=true and supply `maskKey` (4 bytes).
//                       If `maskKey` is empty, a deterministic
//                       all-zero key is used (sufficient because
//                       masking is anti-cache, not anti-tamper).
std::string encodeFrame(Opcode opcode, const std::string &payload,
                        bool mask = false,
                        const std::string &maskKey = "");

// Build a CLOSE frame with a status code (RFC 6455 §7.4) and optional
// reason. Both the runtime and tests use this to terminate cleanly.
std::string encodeCloseFrame(uint16_t code, const std::string &reason = "");

} // namespace WsPure
