// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "vmwrap_pure.h"

#include <cctype>
#include <cstdint>
#include <sstream>

namespace VmWrapPure {

namespace {

bool isAlnumDashUnderscore(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

std::string validateName(const std::string &n, const char *what) {
  if (n.empty()) return std::string(what) + " is empty";
  if (n.size() > 63) return std::string(what) + " too long (>63 chars): '" + n + "'";
  if (n[0] == '-' || n[0] == '.')
    return std::string(what) + " must not start with '-' or '.': '" + n + "'";
  for (char c : n)
    if (!isAlnumDashUnderscore(c))
      return std::string(what) + " contains forbidden char (allowed: [A-Za-z0-9_-]): '" + n + "'";
  return "";
}

bool segmentHasDotDot(const std::string &s) {
  // Strict ".." check: a path segment that's literally "..".
  size_t i = 0;
  while (i < s.size()) {
    size_t j = s.find('/', i);
    if (j == std::string::npos) j = s.size();
    if (j - i == 2 && s[i] == '.' && s[i+1] == '.') return true;
    i = j + 1;
  }
  return false;
}

} // anon

std::string validateVmName(const std::string &n)   { return validateName(n, "VM name"); }
std::string validateJailName(const std::string &n) { return validateName(n, "jail name"); }

std::string validateDataset(const std::string &d) {
  if (d.empty()) return "";
  if (d.size() > 255) return "dataset path too long: '" + d + "'";
  if (d.front() == '/' || d.back() == '/')
    return "dataset must not start or end with '/': '" + d + "'";
  if (segmentHasDotDot(d))
    return "dataset must not contain '..' segments: '" + d + "'";
  if (!std::isalpha(static_cast<unsigned char>(d.front())))
    return "dataset must start with a letter: '" + d + "'";
  for (char c : d) {
    if (std::isalnum(static_cast<unsigned char>(c))) continue;
    if (c == '_' || c == '-' || c == '.' || c == '/' || c == ':') continue;
    return "dataset contains forbidden char (allowed: [A-Za-z0-9_.:/-]): '" + d + "'";
  }
  return "";
}

std::string validateTap(int n) {
  if (n == -1) return "";
  if (n < 0 || n > 9999) return "tap index out of range (0..9999): " + std::to_string(n);
  return "";
}

std::string validateNmdm(int n) {
  if (n == -1) return "";
  if (n < 0 || n > 9999) return "nmdm index out of range (0..9999): " + std::to_string(n);
  return "";
}

std::string validateRulesetNum(unsigned n) {
  if (n == 0)         return "ruleset number 0 is the 'derive' sentinel; pass 1..65535";
  if (n > 65535)      return "ruleset number out of range (1..65535): " + std::to_string(n);
  return "";
}

std::string validateSpec(const WrapSpec &s) {
  if (auto e = validateVmName(s.vmName);   !e.empty()) return e;
  if (auto e = validateJailName(s.jailName); !e.empty()) return e;
  if (auto e = validateDataset(s.dataset); !e.empty()) return e;
  if (auto e = validateTap(s.tap);         !e.empty()) return e;
  if (auto e = validateNmdm(s.nmdm);       !e.empty()) return e;
  if (s.rulesetNum != 0)
    if (auto e = validateRulesetNum(s.rulesetNum); !e.empty()) return e;
  return "";
}

unsigned deriveRulesetNum(const std::string &jailName) {
  // FNV-1a 32-bit, then fold into 100..199. Deterministic, no
  // surprises across runs. Two jail names CAN collide here but
  // that's harmless until the operator runs both at once on the
  // same host — at which point they pass --ruleset N to
  // disambiguate. We document this in the runtime.
  uint32_t h = 2166136261u;
  for (char c : jailName) {
    h ^= static_cast<uint8_t>(c);
    h *= 16777619u;
  }
  return 100u + (h % 100u);
}

std::string defaultJailPath(const std::string & /*jailName*/) {
  // "/" matches vm-bhyve's convention. The jail still has its own
  // vnet, devfs ruleset, and allow.vmm gate — those are the real
  // walls; the path mostly affects how much of the host filesystem
  // the bhyve user-space process inside the jail can read. An
  // operator who wants a tighter chroot passes --path explicitly.
  return "/";
}

std::string buildDevfsRuleset(const WrapSpec &spec) {
  WrapSpec s = spec;
  if (s.rulesetNum == 0) s.rulesetNum = deriveRulesetNum(s.jailName);

  std::ostringstream os;
  os << "[crate_vmwrap_" << s.jailName << "=" << s.rulesetNum << "]\n";
  os << "add include $devfsrules_hide_all\n";
  os << "add include $devfsrules_unhide_basic\n";
  os << "add include $devfsrules_unhide_login\n";
  os << "add path 'vmm/" << s.vmName << "' unhide\n";
  os << "add path vmmctl unhide\n";
  if (s.nmdm >= 0)
    os << "add path 'nmdm" << s.nmdm << "*' unhide\n";
  if (s.tap >= 0)
    os << "add path tap" << s.tap << " unhide\n";
  return os.str();
}

std::string buildJailConfFragment(const WrapSpec &spec) {
  WrapSpec s = spec;
  if (s.rulesetNum == 0) s.rulesetNum = deriveRulesetNum(s.jailName);
  std::string path = s.jailPath.empty() ? defaultJailPath(s.jailName) : s.jailPath;

  std::ostringstream os;
  os << s.jailName << " {\n";
  os << "    # vnet so the tap lives inside the jail's network stack\n";
  os << "    vnet;\n";
  if (s.tap >= 0)
    os << "    vnet.interface = \"tap" << s.tap << "\";\n";
  os << "\n";
  os << "    # Required: lets the jail call vmm syscalls\n";
  os << "    allow.vmm;\n";
  os << "\n";
  os << "    # Don't let the cage raise its own limits\n";
  os << "    allow.raw_sockets = 0;\n";
  os << "    allow.sysvipc = 0;\n";
  os << "\n";
  os << "    # Only the devfs nodes from the ruleset above\n";
  os << "    devfs_ruleset = " << s.rulesetNum << ";\n";
  os << "\n";
  os << "    path = \"" << path << "\";\n";
  os << "    host.hostname = \"" << s.jailName << "\";\n";
  os << "\n";
  os << "    # No userland of its own; bhyve is launched via jexec from outside.\n";
  os << "    persist;\n";
  os << "}\n";
  return os.str();
}

std::vector<std::string> buildDevfsReloadArgv() {
  return {"/usr/sbin/service", "devfs", "restart"};
}

std::vector<std::string> buildJailCreateArgv(const std::string &fragmentPath) {
  return {"/usr/sbin/jail", "-c", "-f", fragmentPath};
}

std::vector<std::string> buildZfsJailArgv(const std::string &jailName,
                                          const std::string &dataset) {
  return {"/sbin/zfs", "jail", jailName, dataset};
}

std::string buildBhyveInvocationHint(const WrapSpec &s) {
  std::ostringstream os;
  os << "# Operator-edit to taste; vm-wrap doesn't run this for you.\n";
  os << "jexec " << s.jailName << " \\\n";
  os << "    bhyve -A -H -P -S \\\n";
  os << "          -c 2 -m 1G \\\n";
  os << "          -s 0:0,hostbridge \\\n";
  if (s.tap >= 0)
    os << "          -s 1:0,virtio-net,tap" << s.tap << " \\\n";
  if (!s.dataset.empty()) {
    // Suggest the disk image lives at /dev/zvol/<dataset>/disk0 by
    // default. Operator overrides if they laid out the dataset
    // differently.
    os << "          -s 2:0,virtio-blk,/dev/zvol/" << s.dataset << "/disk0 \\\n";
  } else {
    os << "          -s 2:0,virtio-blk,/path/to/disk.img \\\n";
  }
  os << "          -s 31:0,lpc \\\n";
  if (s.nmdm >= 0)
    os << "          -l com1,/dev/nmdm" << s.nmdm << "A \\\n";
  os << "          " << s.vmName << "\n";
  return os.str();
}

} // namespace VmWrapPure
