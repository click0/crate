// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for WireGuard configuration generation.
//
// Operators run `crate vpn wireguard render-conf <spec>` to produce
// a wg-quick-compatible config file from a small YAML/CLI spec. The
// runtime side (CLI) feeds key material from disk; this module
// validates the inputs and renders the canonical INI text.
//
// Why it's a separate command, not auto-integrated with `crate run`:
// WireGuard requires the `if_wg` kernel module on FreeBSD 13+ and
// privileged interface creation. Until crate(8) ships a vetted
// integration path (proper RAII for interface teardown, route
// management, jail-side IPv6 RA suppression), the pragmatic step is
// to give operators a tool that emits a correct config they can
// apply with `wg-quick up <conf>`.
//

#include <cstdint>
#include <string>
#include <vector>

namespace WireguardPure {

// --- Key validation ---

// WireGuard keys (private, public, preshared) are 32 raw bytes
// rendered as base64. The wire format is exactly 44 chars: 43 of
// the base64 alphabet plus one `=` pad character.
//
// Returns "" if the key is well-formed; otherwise a one-line reason
// suitable for the CLI's error message.
std::string validateKey(const std::string &keyB64);

// Validate a port number string for `ListenPort = N`. Returns "" on
// success. Range: 1..65535.
std::string validatePort(const std::string &port);

// Validate an `AllowedIPs` entry: `<ip>/<prefix>` for IPv4 or IPv6.
// Lightweight syntactic check — does not parse the address with
// inet_pton (we want this header-only).
std::string validateCidr(const std::string &cidr);

// Validate an `Endpoint` host:port form. Host can be IPv4 literal,
// IPv6 literal in brackets, or hostname (RFC 1123).
std::string validateEndpoint(const std::string &endpoint);

// --- Spec types (caller fills these in from YAML / CLI flags) ---

struct InterfaceSpec {
  std::string privateKey;     // base64
  std::vector<std::string> addresses; // CIDR, e.g. "10.0.0.1/24"
  std::string listenPort;      // optional, empty => omit
  std::string fwmark;          // optional
  std::vector<std::string> dns;       // optional resolvers
  std::vector<std::string> mtu;       // single-element optional
};

struct PeerSpec {
  std::string publicKey;       // base64 — required
  std::string presharedKey;    // base64 — optional
  std::vector<std::string> allowedIps;  // CIDR list — required (≥1)
  std::string endpoint;        // host:port — optional
  std::string persistentKeepalive;  // seconds — optional
  std::string description;     // free-form, emitted as `# desc`
};

// --- Validation that combines spec + key checks ---

// Walks the InterfaceSpec + PeerSpec list and returns the first
// validation error found, or "" if everything is acceptable.
std::string validateConfig(const InterfaceSpec &iface,
                           const std::vector<PeerSpec> &peers);

// --- Rendering ---

// Render the canonical wg-quick INI form. Caller is expected to have
// already run `validateConfig()`; render() does no I/O and silently
// elides empty optional fields. Output ends with a trailing newline.
std::string renderConf(const InterfaceSpec &iface,
                       const std::vector<PeerSpec> &peers);

} // namespace WireguardPure
