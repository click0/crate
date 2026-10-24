// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// Runtime for `crate audit <target>` (1.1.61, TODO §17.4). Finds the
// jail, runs the probe script from JailAuditPure inside it through
// JailExec (jail_attach as root, exec_in_jail through the privops
// socket otherwise) and renders the report. Read-only on the host; the
// only side effects are the two outbound probes inside the jail (one
// TCP connect to the default gateway, one DNS lookup) — `--offline`
// skips them.
//

#include "args.h"
#include "commands.h"
#include "doctor_pure.h"
#include "jail_audit_pure.h"
#include "jail_query.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <iostream>
#include <optional>
#include <string>

#define ERR(msg...) ERR2("audit", msg)

namespace {

std::optional<JailQuery::JailInfo> resolve(const std::string &t) {
  auto j = JailQuery::getJailByName(t);
  if (j) return j;
  try {
    int id = std::stoi(t);
    return JailQuery::getJailByJid(id);
  } catch (...) { return std::nullopt; }
}

} // anon

bool jailAuditCommand(const Args &args) {
  auto jail = resolve(args.auditTarget);
  if (!jail)
    ERR("container '" << args.auditTarget << "' not found or not running")

  JailAuditPure::HostContext ctx;
  ctx.jailName = jail->name;
  ctx.jid      = jail->jid;
  ctx.offline  = args.auditOffline;
  ctx.dnsName  = args.auditDnsName;
  // Host-side values the in-jail numbers are compared against. Both
  // best-effort: a missing sysctl only loses the comparison.
  try { ctx.hostHostid = std::to_string(Util::getSysctlUInt64("kern.hostid")); } catch (...) {}
  try { ctx.hostHostname = Util::getSysctlString("kern.hostname"); } catch (...) {}

  // One exec: the script prints every section itself, so a tool that is
  // missing inside the jail shows up as text in its section rather than
  // as a failed round trip. dnsName was validated (hostname charset) by
  // Args::validate before it was pasted into the script.
  std::string script = JailAuditPure::probeScript(ctx.offline, ctx.dnsName);
  std::string out = JailExec::execInJailGetOutput(jail->jid, {CRATE_PATH_SH, "-c", script},
                                                  "root", "audit probe");

  auto report = JailAuditPure::buildReport(out, ctx);

  if (args.auditJson) {
    std::cout << DoctorPure::renderJson(report) << std::endl;
  } else {
    std::cout << "crate audit: " << jail->name << " (jid " << jail->jid
              << "), seen from inside the jail\n\n";
    std::cout << DoctorPure::renderText(report, args.noColor);
  }

  // Like doctor: false on WARN or FAIL so the exit code is non-zero.
  return DoctorPure::exitCodeFor(report) == 0;
}
