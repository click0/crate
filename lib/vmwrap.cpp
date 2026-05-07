// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// `crate vm-wrap <vmname> --jail <name> [--dataset DS] [--tap N]
//                          [--nmdm N] [--path P] [--ruleset N]
//                          [--output-dir DIR]`
//
// FreeBSD-flavoured analogue of Firecracker's jailer. Renders a
// devfs ruleset, a jail.conf fragment and a `jexec ... bhyve ...`
// invocation hint that an operator can use to enclose an existing
// bhyve VM in a vnet jail without crate owning the VM lifecycle.
//
// Default mode prints the three artefacts to stdout, separated by
// shell-comment-ed banners. With --output-dir DIR they are written
// to:
//
//     DIR/devfs.snippet         # paste into /etc/devfs.rules
//     DIR/<jail>.jail.conf      # use with `jail -c -f`
//     DIR/<jail>.bhyve.sh       # operator-editable launch hint
//
// vm-wrap does NOT execute side-effects (no service devfs restart,
// no jail -c, no zfs jail). The argv builders for those steps
// live in lib/vmwrap_pure.{h,cpp} so a future --apply mode can
// drive them; until that lands the operator runs them by hand.
//

#include "args.h"
#include "commands.h"
#include "err.h"
#include "util.h"
#include "vmwrap_pure.h"

#include <rang.hpp>

#include <fstream>
#include <iostream>
#include <string>

#define ERR(msg...) ERR2("vm-wrap", msg)

namespace {

void writeFile(const std::string &path, const std::string &content) {
  std::ofstream f(path);
  if (!f) ERR("failed to open '" << path << "' for writing")
  f << content;
  if (!f) ERR("failed to write '" << path << "'")
}

void printBanner(const std::string &title) {
  std::cout << rang::fg::cyan
            << "# === " << title << " ==="
            << rang::style::reset << "\n";
}

} // anon

bool vmWrapCommand(const Args &args) {
  VmWrapPure::WrapSpec s;
  s.vmName     = args.vmWrapVmName;
  s.jailName   = args.vmWrapJailName;
  s.dataset    = args.vmWrapDataset;
  s.tap        = args.vmWrapTap;
  s.nmdm       = args.vmWrapNmdm;
  s.jailPath   = args.vmWrapPath;
  s.rulesetNum = args.vmWrapRuleset;

  if (auto e = VmWrapPure::validateSpec(s); !e.empty()) ERR(e)

  // Resolve the derived ruleset number once so the artefacts agree.
  if (s.rulesetNum == 0)
    s.rulesetNum = VmWrapPure::deriveRulesetNum(s.jailName);

  auto devfs   = VmWrapPure::buildDevfsRuleset(s);
  auto jailcf  = VmWrapPure::buildJailConfFragment(s);
  auto hint    = VmWrapPure::buildBhyveInvocationHint(s);

  if (args.vmWrapOutputDir.empty()) {
    // Print mode (default): three labelled blocks to stdout.
    printBanner("devfs.rules block (paste into /etc/devfs.rules)");
    std::cout << devfs << "\n";
    printBanner("jail.conf fragment (use with `jail -c -f <path>`)");
    std::cout << jailcf << "\n";
    printBanner("bhyve invocation hint");
    std::cout << hint;
    std::cerr << rang::fg::yellow
              << "vm-wrap: print-only mode; nothing was written. "
              << "Pass --output-dir DIR to dump artefacts to files, "
              << "or follow docs/bhyve-jailer.md for the manual recipe."
              << rang::style::reset << std::endl;
    return true;
  }

  auto dir = args.vmWrapOutputDir;
  // Create the directory if absent (mode 0700 — these aren't
  // secrets but the bhyve invocation hint may include disk paths
  // and tap indices the operator considers internal).
  if (!Util::Fs::dirExists(dir)) {
    Util::Fs::mkdir(dir, 0700);
  }

  auto pDevfs  = STR(dir << "/devfs.snippet");
  auto pJail   = STR(dir << "/" << s.jailName << ".jail.conf");
  auto pBhyve  = STR(dir << "/" << s.jailName << ".bhyve.sh");

  writeFile(pDevfs, devfs);
  writeFile(pJail,  jailcf);
  writeFile(pBhyve, hint);

  std::cout << rang::fg::green
            << "vm-wrap: wrote 3 artefacts to " << dir << ":"
            << rang::style::reset << "\n";
  std::cout << "  " << pDevfs  << "  (paste into /etc/devfs.rules, then `service devfs restart`)\n";
  std::cout << "  " << pJail   << "  (run `jail -c -f " << pJail << "`)\n";
  std::cout << "  " << pBhyve  << "  (edit, then run from inside the cage)\n";
  if (!s.dataset.empty()) {
    std::cout << "\n";
    std::cout << "After `jail -c`, delegate the dataset:\n";
    std::cout << "  zfs jail " << s.jailName << " " << s.dataset << "\n";
  }
  return true;
}
