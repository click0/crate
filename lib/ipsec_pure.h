// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for IPsec configuration generation. Sister tool to
// lib/wireguard_pure.cpp; renders strongSwan-style `ipsec.conf` from
// a small YAML spec. Operators run
//
//   crate vpn ipsec render-conf <spec.yml>
//
// and pipe the output into /usr/local/etc/ipsec.conf or include it
// from a `conn` snippet directory.
//
// As with WireGuard, full kernel-level integration with crate jails
// is a separate runtime concern (TODO). This module is the
// validate-and-render half — purely testable, no I/O.
//
// We target IKEv2 with PSK / pubkey authentication. The renderer
// emits a strongSwan-style `conn` block per tunnel, keeping the
// section names operators already see in tutorials.
//

#include <string>
#include <vector>

namespace IpsecPure {

// --- Validators ---

// Validate `host` for `left=` / `right=`. Accepts IPv4 literal,
// bracketed IPv6 literal `%any`, or RFC 1123 hostname.
std::string validateHost(const std::string &host);

// Validate a `subnet=` entry — CIDR (IPv4 prefix 0..32 / IPv6 0..128).
// Differs from WireguardPure::validateCidr only in the error string.
std::string validateSubnet(const std::string &subnet);

// Validate cipher proposal strings like
// "aes256-sha256-modp2048" / "aes128gcm16-prfsha256-x25519". Just a
// syntactic check: alnum + '-', length 1..128.
std::string validateProposal(const std::string &p);

// Validate `auto=` — strongSwan accepts: ignore | add | route | start.
std::string validateAuto(const std::string &v);

// Validate `authby=` — strongSwan accepts: psk | pubkey | rsasig |
// ecdsasig | never.
std::string validateAuthby(const std::string &v);

// --- Spec ---

struct ConnSpec {
  std::string name;            // strongSwan section name; ASCII alnum / -_
  std::string left;            // local endpoint
  std::vector<std::string> leftSubnet;
  std::string leftId;          // optional ID override
  std::string right;           // remote endpoint
  std::vector<std::string> rightSubnet;
  std::string rightId;
  std::string ike;             // optional cipher proposal
  std::string esp;             // optional cipher proposal
  std::string keyExchange;     // ike | ikev1 | ikev2
  std::string authBy;          // psk | pubkey | ...
  std::string autoStart;       // ignore | add | route | start
  std::string description;     // free-form, emitted as a `# desc` line
};

// Validate a connection name. Rules:
//   - non-empty, ≤32 chars
//   - allowed: [A-Za-z0-9._-]
//   - reserved: %default (strongSwan keyword)
std::string validateConnName(const std::string &name);

// Walk the list and return the first error (with `conn #N` prefix
// for multi-conn files). Returns "" on success.
std::string validateConfig(const std::vector<ConnSpec> &conns);

// --- Renderer ---

// Render the strongSwan `ipsec.conf` from validated specs. Output
// ends with a trailing newline.
std::string renderConf(const std::vector<ConnSpec> &conns);

} // namespace IpsecPure
