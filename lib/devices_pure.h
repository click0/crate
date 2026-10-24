// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Device classes (1.1.62, TODO §17.5 — firejail --nosound/--novideo/
// --no3d/--noinput/--nou2f, inverted: everything is hidden unless the
// spec asks for a class).
//
//   devices:
//       sound: true      # /dev/dsp*, mixer*, sndstat, audio*, midi*
//       gpu: true        # /dev/dri, dri/*, drm/*, nvidia*
//       video: true      # /dev/video*  (cameras)
//       input: true      # /dev/input/* (evdev: keyboards, mice, pads)
//       usb: true        # /dev/usb/*, usbctl, ugen*, uhid*, u2f*
//       serial: true     # /dev/cua*, ttyu*, ttyU*
//   devices: [sound, gpu]      # list form
//   devices: all               # the host's whole /dev (pre-1.1.62 behaviour)
//
// `crate run` mounts the jail's devfs from the host before the jail
// exists, so no ruleset applies to it on its own and the container sees
// every device of the host. Since 1.1.62 every jail gets a PRIVATE devfs
// ruleset: hide everything, unhide the basic nodes (null, zero, random,
// urandom, crypto, tty, ptmx, pts/*, fd/*, stdin/stdout/stderr, fuse,
// zfs; bpf* with the `net` option), then the classes the spec enables.
// `terminal/devfs_ruleset: N` stays the escape hatch: the operator's
// ruleset is `include`d instead of the built-in base and the classes
// are added on top.
//
// This file is the pure half: the class table, the rule text and the
// ruleset number. lib/run.cpp applies it (devfs(8) as root, the
// apply_devfs_rules privops verb otherwise).
//

#include <string>
#include <vector>

namespace DevicesPure {

struct Devices {
  bool sound  = false;
  bool gpu    = false;
  bool video  = false;
  bool input  = false;
  bool usb    = false;
  bool serial = false;
  bool all    = false;   // `devices: all`: no hiding at all

  bool any() const { return sound || gpu || video || input || usb || serial; }
  // union (used by Spec merge: a template's classes plus the spec's)
  void merge(const Devices &o);
};

// The class names, in canonical order.
const std::vector<std::string> &classNames();

// Set one class by name. false when the name is not a class.
bool setClass(Devices &d, const std::string &name, bool value);

// Human-readable list: "sound, gpu" / "none" / "all".
std::string describe(const Devices &d);

// devfs(8) path globs (relative to the mount, no leading slash) one
// class unhides. Empty for an unknown name.
std::vector<std::string> patternsFor(const std::string &cls);

// Every pattern of the enabled classes, class order, no duplicates.
std::vector<std::string> unhidePatterns(const Devices &d);

// The built-in base: "hide", then the basic nodes. `withBpf` adds
// "path bpf* unhide" (dhclient and tcpdump inside a vnet jail).
std::vector<std::string> baseRules(bool withBpf);

// The complete rule list for one jail, each entry a devfs rulespec
// ("hide" | "include N" | "path GLOB unhide") ready for
// `devfs rule -s N add <rulespec>`:
//   customRuleset < 0 : baseRules(withBpf) + classes
//   customRuleset >= 1: "include <customRuleset>" + classes
std::vector<std::string> buildRules(const Devices &d, int customRuleset, bool withBpf);

// The private ruleset number for this crate(1) process: 10000 + pid %
// 50000 — above the stock 1..5 and the numbers operators pick by hand,
// unique among running jails (pids are), reused only after the owner is
// long gone (the applier deletes the set before filling it).
unsigned rulesetNumberFor(long pid);

// `crate validate` notes for classes that are a real privilege grant.
std::vector<std::string> warnings(const Devices &d);

} // namespace DevicesPure
