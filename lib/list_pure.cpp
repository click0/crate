// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "list_pure.h"

#include <algorithm>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>

namespace ListPure {

void renderJson(std::ostream &out, const std::vector<Entry> &entries) {
  out << "[\n";
  for (size_t i = 0; i < entries.size(); i++) {
    auto &e = entries[i];
    out << "  {"
        << "\"jid\":" << e.jid
        << ",\"name\":\"" << e.name << "\""
        << ",\"hostname\":\"" << e.hostname << "\""
        << ",\"ip\":\"" << e.ip << "\""
        << ",\"path\":\"" << e.path << "\""
        << ",\"ports\":\"" << e.ports << "\""
        << ",\"mounts\":\"" << e.mounts << "\""
        << ",\"healthcheck\":" << (e.hasHealthcheck ? "true" : "false")
        << "}";
    if (i + 1 < entries.size()) out << ",";
    out << "\n";
  }
  out << "]\n";
}

void renderTable(std::ostream &out, const std::vector<Entry> &entries) {
  if (entries.empty()) {
    out << "No running crate containers.\n";
    return;
  }

  size_t wJid = 3, wName = 4, wIp = 10, wHostname = 8, wPorts = 5, wMounts = 6;
  for (auto &e : entries) {
    wJid      = std::max(wJid, std::to_string(e.jid).size());
    wName     = std::max(wName, e.name.size());
    wIp       = std::max(wIp, e.ip.empty() ? size_t(1) : e.ip.size());
    wHostname = std::max(wHostname, e.hostname.size());
    wPorts    = std::max(wPorts, e.ports.empty() ? size_t(1) : e.ports.size());
    wMounts   = std::max(wMounts, e.mounts.empty() ? size_t(1) : e.mounts.size());
  }

  out << std::left
      << std::setw(wJid + 2) << "JID"
      << std::setw(wName + 2) << "NAME"
      << std::setw(wIp + 2) << "IP"
      << std::setw(wHostname + 2) << "HOSTNAME"
      << std::setw(wPorts + 2) << "PORTS"
      << std::setw(wMounts + 2) << "MOUNTS"
      << "HC\n";

  for (auto &e : entries) {
    out << std::left
        << std::setw(wJid + 2) << e.jid
        << std::setw(wName + 2) << e.name
        << std::setw(wIp + 2) << (e.ip.empty() ? "-" : e.ip)
        << std::setw(wHostname + 2) << e.hostname
        << std::setw(wPorts + 2) << (e.ports.empty() ? "-" : e.ports)
        << std::setw(wMounts + 2) << (e.mounts.empty() ? "-" : e.mounts)
        << (e.hasHealthcheck ? "Y" : "-")
        << "\n";
  }

  out << "\n" << entries.size() << " running container"
      << (entries.size() != 1 ? "s" : "") << ".\n";
}

std::string renderJsonStr(const std::vector<Entry> &entries) {
  std::ostringstream ss; renderJson(ss, entries); return ss.str();
}

std::string renderTableStr(const std::vector<Entry> &entries) {
  std::ostringstream ss; renderTable(ss, entries); return ss.str();
}

}
