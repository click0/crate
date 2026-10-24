// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "devices_pure.h"

#include <algorithm>

namespace DevicesPure {

void Devices::merge(const Devices &o) {
  sound  = sound  || o.sound;
  gpu    = gpu    || o.gpu;
  video  = video  || o.video;
  input  = input  || o.input;
  usb    = usb    || o.usb;
  serial = serial || o.serial;
  all    = all    || o.all;
}

const std::vector<std::string> &classNames() {
  static const std::vector<std::string> v = {"sound", "gpu", "video", "input", "usb", "serial"};
  return v;
}

namespace {

bool *fieldFor(Devices &d, const std::string &name) {
  if (name == "sound")  return &d.sound;
  if (name == "gpu")    return &d.gpu;
  if (name == "video")  return &d.video;
  if (name == "input")  return &d.input;
  if (name == "usb")    return &d.usb;
  if (name == "serial") return &d.serial;
  return nullptr;
}

bool enabled(const Devices &d, const std::string &name) {
  if (name == "sound")  return d.sound;
  if (name == "gpu")    return d.gpu;
  if (name == "video")  return d.video;
  if (name == "input")  return d.input;
  if (name == "usb")    return d.usb;
  if (name == "serial") return d.serial;
  return false;
}

} // anon

bool setClass(Devices &d, const std::string &name, bool value) {
  bool *f = fieldFor(d, name);
  if (!f) return false;
  *f = value;
  return true;
}

std::string describe(const Devices &d) {
  if (d.all) return "all";
  std::string out;
  for (const auto &c : classNames())
    if (enabled(d, c)) out += (out.empty() ? "" : ", ") + c;
  return out.empty() ? "none" : out;
}

std::vector<std::string> patternsFor(const std::string &cls) {
  if (cls == "sound")  return {"dsp*", "mixer*", "sndstat", "audio*", "midi*"};
  if (cls == "gpu")    return {"dri", "dri/*", "drm", "drm/*", "nvidia*"};
  if (cls == "video")  return {"video*"};
  if (cls == "input")  return {"input", "input/*"};
  if (cls == "usb")    return {"usb", "usb/*", "usbctl", "ugen*", "uhid*", "u2f*"};
  if (cls == "serial") return {"cua*", "ttyu*", "ttyU*"};
  return {};
}

std::vector<std::string> unhidePatterns(const Devices &d) {
  std::vector<std::string> out;
  for (const auto &c : classNames()) {
    if (!enabled(d, c)) continue;
    for (const auto &p : patternsFor(c))
      if (std::find(out.begin(), out.end(), p) == out.end()) out.push_back(p);
  }
  return out;
}

std::vector<std::string> baseRules(bool withBpf) {
  // /etc/defaults/devfs.rules: devfsrules_hide_all + unhide_basic +
  // unhide_login + the jail set's fuse and zfs, spelled out so the jail
  // does not depend on rulesets 1..3 being loaded on the host. `tty`
  // (the controlling-terminal alias, nothing of the host) is added on
  // top because shells and sudo open it.
  std::vector<std::string> r = {
    "hide",
    "path null unhide", "path zero unhide", "path crypto unhide",
    "path random unhide", "path urandom unhide",
    "path tty unhide", "path ptmx unhide", "path pts unhide", "path pts/* unhide",
    "path fd unhide", "path fd/* unhide",
    "path stdin unhide", "path stdout unhide", "path stderr unhide",
    "path fuse unhide", "path zfs unhide",
  };
  if (withBpf) r.push_back("path bpf* unhide");
  return r;
}

std::vector<std::string> buildRules(const Devices &d, int customRuleset, bool withBpf) {
  std::vector<std::string> rules;
  if (customRuleset >= 1) rules.push_back("include " + std::to_string(customRuleset));
  else rules = baseRules(withBpf);
  for (const auto &p : unhidePatterns(d)) rules.push_back("path " + p + " unhide");
  return rules;
}

unsigned rulesetNumberFor(long pid) {
  if (pid < 0) pid = -pid;
  return 10000u + (unsigned)(pid % 50000);
}

std::vector<std::string> warnings(const Devices &d) {
  std::vector<std::string> w;
  if (d.all)
    w.push_back("devices: all — the host's whole /dev is visible inside the jail (disks, memory, keyboards); name the classes the program needs instead");
  if (d.input)
    w.push_back("devices/input exposes /dev/input/*: everything typed on the host's keyboard is readable from inside the jail");
  if (d.usb)
    w.push_back("devices/usb exposes every USB device of the host (ugen*, uhid*), not one of them");
  if (d.serial)
    w.push_back("devices/serial exposes the host's serial ports (cua*, ttyu*)");
  return w;
}

} // namespace DevicesPure
