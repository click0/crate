// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "inspect_pure.h"

#include <cstdio>
#include <iomanip>
#include <sstream>

namespace InspectPure {

std::string escapeJsonString(const std::string &in) {
  std::ostringstream o;
  for (unsigned char c : in) {
    switch (c) {
      case '"':  o << "\\\""; break;
      case '\\': o << "\\\\"; break;
      case '\b': o << "\\b";  break;
      case '\f': o << "\\f";  break;
      case '\n': o << "\\n";  break;
      case '\r': o << "\\r";  break;
      case '\t': o << "\\t";  break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
          o << buf;
        } else {
          o << static_cast<char>(c);
        }
    }
  }
  return o.str();
}

namespace {

// Indent helper: returns N*2 spaces.
std::string ind(int n) { return std::string((size_t)n * 2, ' '); }

void emitStr(std::ostringstream &o, int depth, const char *key,
             const std::string &val, bool last = false) {
  o << ind(depth) << "\"" << key << "\": \""
    << escapeJsonString(val) << "\"" << (last ? "" : ",") << "\n";
}

void emitInt(std::ostringstream &o, int depth, const char *key,
             long val, bool last = false) {
  o << ind(depth) << "\"" << key << "\": " << val
    << (last ? "" : ",") << "\n";
}

void emitBool(std::ostringstream &o, int depth, const char *key,
              bool val, bool last = false) {
  o << ind(depth) << "\"" << key << "\": " << (val ? "true" : "false")
    << (last ? "" : ",") << "\n";
}

void emitMap(std::ostringstream &o, int depth, const char *key,
             const std::map<std::string, std::string> &m, bool last = false) {
  o << ind(depth) << "\"" << key << "\": {";
  if (m.empty()) {
    o << "}" << (last ? "" : ",") << "\n";
    return;
  }
  o << "\n";
  size_t i = 0;
  for (auto &kv : m) {
    o << ind(depth + 1) << "\"" << escapeJsonString(kv.first) << "\": \""
      << escapeJsonString(kv.second) << "\""
      << (++i == m.size() ? "" : ",") << "\n";
  }
  o << ind(depth) << "}" << (last ? "" : ",") << "\n";
}

void emitInterfaces(std::ostringstream &o, int depth,
                    const std::vector<Interface> &v, bool last = false) {
  o << ind(depth) << "\"interfaces\": [";
  if (v.empty()) {
    o << "]" << (last ? "" : ",") << "\n";
    return;
  }
  o << "\n";
  for (size_t i = 0; i < v.size(); i++) {
    auto &x = v[i];
    o << ind(depth + 1) << "{\n";
    emitStr(o, depth + 2, "name", x.name);
    emitStr(o, depth + 2, "ip4",  x.ip4);
    emitStr(o, depth + 2, "ip6",  x.ip6);
    emitStr(o, depth + 2, "mac",  x.mac, true);
    o << ind(depth + 1) << "}" << (i + 1 == v.size() ? "" : ",") << "\n";
  }
  o << ind(depth) << "]" << (last ? "" : ",") << "\n";
}

void emitMounts(std::ostringstream &o, int depth,
                const std::vector<Mount> &v, bool last = false) {
  o << ind(depth) << "\"mounts\": [";
  if (v.empty()) {
    o << "]" << (last ? "" : ",") << "\n";
    return;
  }
  o << "\n";
  for (size_t i = 0; i < v.size(); i++) {
    auto &x = v[i];
    o << ind(depth + 1) << "{\n";
    emitStr(o, depth + 2, "source", x.source);
    emitStr(o, depth + 2, "target", x.target);
    emitStr(o, depth + 2, "fstype", x.fstype, true);
    o << ind(depth + 1) << "}" << (i + 1 == v.size() ? "" : ",") << "\n";
  }
  o << ind(depth) << "]" << (last ? "" : ",") << "\n";
}

} // anon

std::string renderJson(const InspectData &d) {
  std::ostringstream o;
  o << "{\n";
  emitStr(o, 1, "name",        d.name);
  emitInt(o, 1, "jid",         d.jid);
  emitStr(o, 1, "hostname",    d.hostname);
  emitStr(o, 1, "path",        d.path);
  emitStr(o, 1, "osrelease",   d.osrelease);
  emitMap(o, 1, "jail_params", d.jailParams);
  emitInterfaces(o, 1, d.interfaces);
  emitMounts    (o, 1, d.mounts);
  emitMap(o, 1, "rctl_usage",  d.rctlUsage);
  emitStr(o, 1, "zfs_dataset", d.zfsDataset);
  emitStr(o, 1, "zfs_origin",  d.zfsOrigin);
  emitInt(o, 1, "process_count", d.processCount);

  // GUI block — flat keys, all four together.
  emitBool(o, 1, "has_gui",     d.hasGui);
  emitInt (o, 1, "gui_display", d.guiDisplay);
  emitInt (o, 1, "gui_vnc_port", d.guiVncPort);
  emitInt (o, 1, "gui_ws_port",  d.guiWsPort);
  emitStr (o, 1, "gui_mode",    d.guiMode);

  emitInt(o, 1, "started_at",   d.startedAt);
  emitInt(o, 1, "inspected_at", d.inspectedAt, true);
  o << "}\n";
  return o.str();
}

void applyRctlOutput(const std::string &rctlOut, InspectData &data) {
  size_t i = 0;
  while (i < rctlOut.size()) {
    auto nl = rctlOut.find('\n', i);
    if (nl == std::string::npos) nl = rctlOut.size();
    auto line = rctlOut.substr(i, nl - i);
    i = nl + 1;
    if (line.empty()) continue;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    data.rctlUsage[line.substr(0, eq)] = line.substr(eq + 1);
  }
}

void applyMountOutput(const std::string &mountOut,
                      const std::string &jailRoot,
                      InspectData &data) {
  std::string prefix = jailRoot;
  if (!prefix.empty() && prefix.back() != '/') prefix += "/";

  size_t i = 0;
  while (i < mountOut.size()) {
    auto nl = mountOut.find('\n', i);
    if (nl == std::string::npos) nl = mountOut.size();
    auto line = mountOut.substr(i, nl - i);
    i = nl + 1;

    // Format: "<source> on <target> (<fstype>, ...)"
    auto onPos = line.find(" on ");
    if (onPos == std::string::npos) continue;
    auto parenPos = line.find(" (", onPos);
    if (parenPos == std::string::npos) continue;
    auto endParen = line.find(")", parenPos);
    if (endParen == std::string::npos) continue;

    Mount m;
    m.source = line.substr(0, onPos);
    m.target = line.substr(onPos + 4, parenPos - (onPos + 4));
    auto inside = line.substr(parenPos + 2, endParen - (parenPos + 2));
    auto comma = inside.find(',');
    m.fstype = (comma == std::string::npos) ? inside : inside.substr(0, comma);

    if (m.target == jailRoot
        || (m.target.size() > prefix.size()
            && m.target.compare(0, prefix.size(), prefix) == 0))
      data.mounts.push_back(std::move(m));
  }
}

} // namespace InspectPure
