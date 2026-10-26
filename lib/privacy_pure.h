// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.67 (TODO §17.10, bwrap/firejail `--machine-id` / `--hostname`): the
// `privacy:` spec section — what a program inside the jail learns about
// the machine it runs on.
//
//   privacy:
//     hostid: random          # per-run host UUID + hostid (kern.hostuuid / kern.hostid, /etc/hostid)
//     hostname: random        # per-run jail hostname "crate-<8 hex>"
//
// A jail shares the host's kern.hostuuid/kern.hostid unless the jail is
// created with its own `host.hostuuid` / `host.hostid` parameters; crate
// always passed only `host.hostname=<the host's name>`, so every jail
// identified the machine to anything that reads them (`crate audit`
// warns since 1.1.61). `hostid` can be `host` (the default, as before),
// `random` (a fresh UUID v4 every run) or a literal UUID (stable for the
// crate); `hostname` can be `host`, `random` or a literal host name.
// `kern.hostid` is derived from the UUID the way /etc/rc.d/hostid does:
// the first 32 bits of md5(uuid text). The jail's /etc/hostid gets the
// UUID so rc(8) inside agrees with the kernel.
//
// yaml-free: parsing rules, UUID/hostid arithmetic and the jail(8)
// parameters are unit-tested on Linux; lib/run_jail.cpp applies them.

#pragma once

#include <string>
#include <vector>

namespace PrivacyPure {

enum class Mode { Host, Random, Fixed };

// `privacy/hostid`: "" / "host" -> Host; "random" -> Random; a UUID
// (8-4-4-4-12 hex, any case) -> Fixed with `uuidOut` lower-cased.
// Returns "" or the reason.
std::string parseHostid(const std::string &text, Mode &modeOut, std::string &uuidOut);

// `privacy/hostname`: "" / "host" -> Host; "random" -> Random; a host
// name (letters, digits, '-', '.', <= 63 chars per label, <= 255 total)
// -> Fixed. Returns "" or the reason.
std::string parseHostname(const std::string &text, Mode &modeOut, std::string &nameOut);

// true for xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (hex, any case).
bool isUuid(const std::string &s);

// A UUID v4 from 32 hex digits of randomness (Util::randomHex(16)):
// version nibble 4, variant bits 10. Lower case. "" when `hex32` is not
// 32 hex digits.
std::string uuidFromHex(const std::string &hex32);

// MD5 of `data`, 32 lower-case hex digits (RFC 1321; only used for the
// hostid derivation below, where FreeBSD's rc.d/hostid is the reference).
std::string md5Hex(const std::string &data);

// kern.hostid as /etc/rc.d/hostid derives it: the first 8 hex digits of
// md5(uuid), as an unsigned 32-bit value.
unsigned long hostidFromUuid(const std::string &uuid);

// "crate-<first 8 hex>" for a random hostname.
std::string randomHostname(const std::string &hex);

// The jail(8) parameters for a non-host hostid: {"host.hostuuid=<uuid>",
// "host.hostid=<decimal>"}; empty for Mode::Host.
std::vector<std::string> jailParams(const std::string &uuid);

// Content of the jail's /etc/hostid: the UUID and a newline.
std::string hostidFileContent(const std::string &uuid);

}
