// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.56: pure parsers for a jail's master.passwd(5) and group(5) files.
// crated's exec_in_jail handler used to call getpwnam()/initgroups() in
// the pdfork(2) child, after jail_attach(2), inside a multi-threaded
// daemon — nsdispatch, malloc and file I/O after fork. The parent now
// reads <jailPath>/etc/master.passwd and <jailPath>/etc/group itself and
// hands the child plain integers. No libc name-service calls involved.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace PasswdPure {

struct User {
  std::string name;
  uint32_t uid = 0;
  uint32_t gid = 0;
  std::string loginClass;   // 5th field; "" means the default class
  std::string home;         // 9th field
  std::string shell;        // 10th field
};

// Parse one master.passwd(5) line
// (name:password:uid:gid:class:change:expire:gecos:home:shell).
// Returns false for comments, blank lines and malformed lines (wrong
// field count, non-numeric uid/gid, empty name).
bool parseMasterPasswdLine(const std::string &line, User &out);

// Find `name` in the content of a master.passwd(5) file. Also accepts
// passwd(5) (7 fields: name:password:uid:gid:gecos:home:shell) so a jail
// without a master.passwd still resolves. First match wins. Returns
// false when absent.
bool lookupUser(const std::string &content, const std::string &name, User &out);

// Supplementary groups of `user` from group(5) content
// (name:password:gid:member,member,...). `primaryGid` is placed first
// and never duplicated; the result is what setgroups(2) wants. Malformed
// lines are skipped. Capped at `maxGroups` (NGROUPS_MAX is 1023 on
// FreeBSD; 16 is the portable minimum and more than any jail needs).
std::vector<uint32_t> supplementaryGroups(const std::string &content,
                                          const std::string &user,
                                          uint32_t primaryGid,
                                          size_t maxGroups = 64);

// Upper bound for the two files read from a jail root: a passwd/group
// file beyond this is treated as absent (a jail could make it huge).
constexpr size_t kMaxFileBytes = 4 * 1024 * 1024;

}
