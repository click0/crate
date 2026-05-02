// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ws_pure.h"

#include <atf-c++.hpp>

#include <string>

using WsPure::Frame;
using WsPure::Opcode;
using WsPure::sha1Raw;
using WsPure::base64Encode;
using WsPure::computeAcceptKey;
using WsPure::parseHandshakeRequest;
using WsPure::buildHandshakeResponse;
using WsPure::buildHandshakeRejection;
using WsPure::parseFrame;
using WsPure::encodeFrame;
using WsPure::encodeCloseFrame;

namespace {

std::string hex(const std::string &raw) {
  static const char *d = "0123456789abcdef";
  std::string out;
  for (unsigned char c : raw) {
    out += d[(c >> 4) & 0xf];
    out += d[c & 0xf];
  }
  return out;
}

} // anon

// --- SHA-1 ---

ATF_TEST_CASE_WITHOUT_HEAD(sha1_known_vectors);
ATF_TEST_CASE_BODY(sha1_known_vectors) {
  // RFC 3174 / FIPS 180 test vectors.
  ATF_REQUIRE_EQ(hex(sha1Raw("")),
                 std::string("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
  ATF_REQUIRE_EQ(hex(sha1Raw("abc")),
                 std::string("a9993e364706816aba3e25717850c26c9cd0d89d"));
  ATF_REQUIRE_EQ(hex(sha1Raw("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
                 std::string("84983e441c3bd26ebaae4aa1f95129e5e54670f1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(sha1_long_input_crosses_block_boundary);
ATF_TEST_CASE_BODY(sha1_long_input_crosses_block_boundary) {
  // 1,000,000 'a' characters → known FIPS vector.
  std::string a(1000000, 'a');
  ATF_REQUIRE_EQ(hex(sha1Raw(a)),
                 std::string("34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
}

// --- Base64 ---

ATF_TEST_CASE_WITHOUT_HEAD(base64_rfc4648_vectors);
ATF_TEST_CASE_BODY(base64_rfc4648_vectors) {
  ATF_REQUIRE_EQ(base64Encode(""),       std::string(""));
  ATF_REQUIRE_EQ(base64Encode("f"),      std::string("Zg=="));
  ATF_REQUIRE_EQ(base64Encode("fo"),     std::string("Zm8="));
  ATF_REQUIRE_EQ(base64Encode("foo"),    std::string("Zm9v"));
  ATF_REQUIRE_EQ(base64Encode("foob"),   std::string("Zm9vYg=="));
  ATF_REQUIRE_EQ(base64Encode("fooba"),  std::string("Zm9vYmE="));
  ATF_REQUIRE_EQ(base64Encode("foobar"), std::string("Zm9vYmFy"));
}

// --- WebSocket accept key (RFC 6455 §1.3) ---

ATF_TEST_CASE_WITHOUT_HEAD(accept_key_matches_rfc6455_example);
ATF_TEST_CASE_BODY(accept_key_matches_rfc6455_example) {
  // The canonical example from RFC 6455 §1.3:
  //   Sec-WebSocket-Key:    dGhlIHNhbXBsZSBub25jZQ==
  //   Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
  ATF_REQUIRE_EQ(computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ=="),
                 std::string("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
}

// --- Handshake parsing ---

ATF_TEST_CASE_WITHOUT_HEAD(handshake_parses_valid_request);
ATF_TEST_CASE_BODY(handshake_parses_valid_request) {
  std::string req =
    "GET /api/v1/containers/myjail/console HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Upgrade: websocket\r\n"
    "Connection: keep-alive, Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n";
  auto h = parseHandshakeRequest(req);
  ATF_REQUIRE(h.ok);
  ATF_REQUIRE_EQ(h.path, std::string("/api/v1/containers/myjail/console"));
  ATF_REQUIRE_EQ(h.clientKey, std::string("dGhlIHNhbXBsZSBub25jZQ=="));
  ATF_REQUIRE_EQ(h.version, 13);
}

ATF_TEST_CASE_WITHOUT_HEAD(handshake_tolerates_lowercase_and_mixed_case_headers);
ATF_TEST_CASE_BODY(handshake_tolerates_lowercase_and_mixed_case_headers) {
  std::string req =
    "GET / HTTP/1.1\r\n"
    "host: example.com\r\n"
    "upgrade: websocket\r\n"
    "CONNECTION: Upgrade\r\n"
    "sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-Websocket-Version: 13\r\n"
    "\r\n";
  auto h = parseHandshakeRequest(req);
  ATF_REQUIRE(h.ok);
}

ATF_TEST_CASE_WITHOUT_HEAD(handshake_rejects_missing_key);
ATF_TEST_CASE_BODY(handshake_rejects_missing_key) {
  std::string req =
    "GET / HTTP/1.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n";
  auto h = parseHandshakeRequest(req);
  ATF_REQUIRE(!h.ok);
  ATF_REQUIRE(h.failureReason.find("Sec-WebSocket-Key") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(handshake_rejects_wrong_version);
ATF_TEST_CASE_BODY(handshake_rejects_wrong_version) {
  std::string req =
    "GET / HTTP/1.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 8\r\n"
    "\r\n";
  auto h = parseHandshakeRequest(req);
  ATF_REQUIRE(!h.ok);
  ATF_REQUIRE(h.failureReason.find("Version") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(handshake_rejects_missing_upgrade);
ATF_TEST_CASE_BODY(handshake_rejects_missing_upgrade) {
  std::string req =
    "GET / HTTP/1.1\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n";
  auto h = parseHandshakeRequest(req);
  ATF_REQUIRE(!h.ok);
}

ATF_TEST_CASE_WITHOUT_HEAD(handshake_rejects_non_get);
ATF_TEST_CASE_BODY(handshake_rejects_non_get) {
  std::string req = "POST / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n";
  auto h = parseHandshakeRequest(req);
  ATF_REQUIRE(!h.ok);
}

// --- Handshake response ---

ATF_TEST_CASE_WITHOUT_HEAD(handshake_response_format);
ATF_TEST_CASE_BODY(handshake_response_format) {
  auto resp = buildHandshakeResponse("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
  ATF_REQUIRE(resp.find("HTTP/1.1 101 Switching Protocols\r\n") == 0);
  ATF_REQUIRE(resp.find("Upgrade: websocket\r\n") != std::string::npos);
  ATF_REQUIRE(resp.find("Connection: Upgrade\r\n") != std::string::npos);
  ATF_REQUIRE(resp.find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n")
                != std::string::npos);
  // Headers end with double CRLF.
  ATF_REQUIRE(resp.size() >= 4);
  ATF_REQUIRE_EQ(resp.substr(resp.size() - 4), std::string("\r\n\r\n"));
}

ATF_TEST_CASE_WITHOUT_HEAD(handshake_rejection_includes_reason);
ATF_TEST_CASE_BODY(handshake_rejection_includes_reason) {
  auto resp = buildHandshakeRejection("missing key");
  ATF_REQUIRE(resp.find("400 Bad Request") != std::string::npos);
  ATF_REQUIRE(resp.find("missing key") != std::string::npos);
  ATF_REQUIRE(resp.find("application/json") != std::string::npos);
}

// --- Frame parsing ---

ATF_TEST_CASE_WITHOUT_HEAD(frame_parses_short_unmasked_text);
ATF_TEST_CASE_BODY(frame_parses_short_unmasked_text) {
  // FIN=1, opcode=text, no mask, len=5, payload="hello"
  std::string buf = "\x81\x05hello";
  Frame f;
  int n = parseFrame(buf, f);
  ATF_REQUIRE_EQ(n, 7);
  ATF_REQUIRE(f.fin);
  ATF_REQUIRE(f.opcode == Opcode::Text);
  ATF_REQUIRE(!f.masked);
  ATF_REQUIRE_EQ(f.payload, std::string("hello"));
}

ATF_TEST_CASE_WITHOUT_HEAD(frame_parses_short_masked_text);
ATF_TEST_CASE_BODY(frame_parses_short_masked_text) {
  // From RFC 6455 §5.7: masked "Hello" with key 0x37 0xfa 0x21 0x3d.
  std::string buf;
  buf += (char)0x81;
  buf += (char)0x85;
  buf += (char)0x37; buf += (char)0xfa; buf += (char)0x21; buf += (char)0x3d;
  buf += (char)0x7f; buf += (char)0x9f; buf += (char)0x4d; buf += (char)0x51; buf += (char)0x58;
  Frame f;
  int n = parseFrame(buf, f);
  ATF_REQUIRE_EQ(n, 11);
  ATF_REQUIRE(f.masked);
  ATF_REQUIRE_EQ(f.payload, std::string("Hello"));
}

ATF_TEST_CASE_WITHOUT_HEAD(frame_parses_medium_length);
ATF_TEST_CASE_BODY(frame_parses_medium_length) {
  // 200-byte payload, length encoded as 16-bit (len = 126 marker).
  std::string payload(200, 'A');
  std::string buf;
  buf += (char)0x82;       // FIN, binary
  buf += (char)126;        // 16-bit length
  buf += (char)0x00;
  buf += (char)0xc8;       // 200
  buf += payload;
  Frame f;
  int n = parseFrame(buf, f);
  ATF_REQUIRE_EQ(n, (int)buf.size());
  ATF_REQUIRE(f.opcode == Opcode::Binary);
  ATF_REQUIRE_EQ(f.payload.size(), (size_t)200);
}

ATF_TEST_CASE_WITHOUT_HEAD(frame_returns_zero_when_incomplete);
ATF_TEST_CASE_BODY(frame_returns_zero_when_incomplete) {
  Frame f;
  ATF_REQUIRE_EQ(parseFrame(std::string(""), f), 0);
  ATF_REQUIRE_EQ(parseFrame(std::string("\x81", 1), f), 0);
  // Length says 5 but only 2 payload bytes present.
  std::string partial("\x81\x05" "ab", 4);
  ATF_REQUIRE_EQ(parseFrame(partial, f), 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(frame_rejects_reserved_opcode);
ATF_TEST_CASE_BODY(frame_rejects_reserved_opcode) {
  Frame f;
  // Opcode 0x3 is reserved. NB: a literal-init like "\x83\x00" stops
  // the string at the embedded NUL, so build it explicitly.
  std::string buf("\x83\x00", 2);
  ATF_REQUIRE(parseFrame(buf, f) < 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(frame_rejects_oversized_control_frame);
ATF_TEST_CASE_BODY(frame_rejects_oversized_control_frame) {
  Frame f;
  // PING (0x9) with 200-byte length — control frames must be ≤125.
  std::string buf;
  buf += (char)0x89; buf += (char)126; buf += (char)0x00; buf += (char)0xc8;
  buf += std::string(200, 'x');
  ATF_REQUIRE(parseFrame(buf, f) < 0);
}

// --- Frame encoding (round trip) ---

ATF_TEST_CASE_WITHOUT_HEAD(frame_round_trip_short);
ATF_TEST_CASE_BODY(frame_round_trip_short) {
  auto bytes = encodeFrame(Opcode::Text, "hello world");
  Frame f;
  int n = parseFrame(bytes, f);
  ATF_REQUIRE_EQ(n, (int)bytes.size());
  ATF_REQUIRE(f.opcode == Opcode::Text);
  ATF_REQUIRE_EQ(f.payload, std::string("hello world"));
  ATF_REQUIRE(!f.masked);
}

ATF_TEST_CASE_WITHOUT_HEAD(frame_round_trip_with_mask);
ATF_TEST_CASE_BODY(frame_round_trip_with_mask) {
  std::string key = "\x37\xfa\x21\x3d";
  auto bytes = encodeFrame(Opcode::Text, "Hello", true, key);
  Frame f;
  int n = parseFrame(bytes, f);
  ATF_REQUIRE_EQ(n, (int)bytes.size());
  ATF_REQUIRE(f.masked);
  ATF_REQUIRE_EQ(f.payload, std::string("Hello"));
}

ATF_TEST_CASE_WITHOUT_HEAD(frame_round_trip_medium_and_large);
ATF_TEST_CASE_BODY(frame_round_trip_medium_and_large) {
  std::string p126(200, 'A');
  Frame f;
  ATF_REQUIRE(parseFrame(encodeFrame(Opcode::Binary, p126), f) > 0);
  ATF_REQUIRE_EQ(f.payload, p126);

  std::string p127(70000, 'B');
  ATF_REQUIRE(parseFrame(encodeFrame(Opcode::Binary, p127), f) > 0);
  ATF_REQUIRE_EQ(f.payload, p127);
}

ATF_TEST_CASE_WITHOUT_HEAD(close_frame_encodes_status_code);
ATF_TEST_CASE_BODY(close_frame_encodes_status_code) {
  auto bytes = encodeCloseFrame(1000, "bye");
  Frame f;
  ATF_REQUIRE(parseFrame(bytes, f) > 0);
  ATF_REQUIRE(f.opcode == Opcode::Close);
  ATF_REQUIRE_EQ(f.payload.size(), (size_t)5);
  ATF_REQUIRE_EQ((unsigned char)f.payload[0], (unsigned char)0x03);
  ATF_REQUIRE_EQ((unsigned char)f.payload[1], (unsigned char)0xe8); // 1000
  ATF_REQUIRE_EQ(f.payload.substr(2), std::string("bye"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, sha1_known_vectors);
  ATF_ADD_TEST_CASE(tcs, sha1_long_input_crosses_block_boundary);
  ATF_ADD_TEST_CASE(tcs, base64_rfc4648_vectors);
  ATF_ADD_TEST_CASE(tcs, accept_key_matches_rfc6455_example);
  ATF_ADD_TEST_CASE(tcs, handshake_parses_valid_request);
  ATF_ADD_TEST_CASE(tcs, handshake_tolerates_lowercase_and_mixed_case_headers);
  ATF_ADD_TEST_CASE(tcs, handshake_rejects_missing_key);
  ATF_ADD_TEST_CASE(tcs, handshake_rejects_wrong_version);
  ATF_ADD_TEST_CASE(tcs, handshake_rejects_missing_upgrade);
  ATF_ADD_TEST_CASE(tcs, handshake_rejects_non_get);
  ATF_ADD_TEST_CASE(tcs, handshake_response_format);
  ATF_ADD_TEST_CASE(tcs, handshake_rejection_includes_reason);
  ATF_ADD_TEST_CASE(tcs, frame_parses_short_unmasked_text);
  ATF_ADD_TEST_CASE(tcs, frame_parses_short_masked_text);
  ATF_ADD_TEST_CASE(tcs, frame_parses_medium_length);
  ATF_ADD_TEST_CASE(tcs, frame_returns_zero_when_incomplete);
  ATF_ADD_TEST_CASE(tcs, frame_rejects_reserved_opcode);
  ATF_ADD_TEST_CASE(tcs, frame_rejects_oversized_control_frame);
  ATF_ADD_TEST_CASE(tcs, frame_round_trip_short);
  ATF_ADD_TEST_CASE(tcs, frame_round_trip_with_mask);
  ATF_ADD_TEST_CASE(tcs, frame_round_trip_medium_and_large);
  ATF_ADD_TEST_CASE(tcs, close_frame_encodes_status_code);
}
