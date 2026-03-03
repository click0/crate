// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "config.h"
#include "util.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <dirent.h>
#include <string>
#include <vector>

namespace Config {

static Settings g_settings;
static bool g_loaded = false;

static Settings defaults() {
  Settings s;
  s.prefix = "/var/run/crate";
  s.cache = "/var/cache/crate";
  s.logs = "/var/log/crate";
  s.zfsEnable = false;
  s.zfsZpool = "";
  s.zfsOptions = "-o compress=lz4 -o atime=off";
  s.networkInterface = "";
  s.defaultBridge = "";
  s.staticMacDefault = false;
  s.bootstrapMethod = "base_txz";
  s.securelevel = 2;
  s.childrenMax = 0;
  s.searchPath = {".", STR(Util::Fs::getUserHomeDir() << "/.local/share/crate"),
                  "/usr/local/share/crate"};
  s.compressXzOptions = "-T0";
  return s;
}

static void applyYaml(Settings &s, const YAML::Node &cfg) {
  if (!cfg.IsMap())
    return;

  if (cfg["prefix"])           s.prefix = cfg["prefix"].as<std::string>();
  if (cfg["cache"])            s.cache = cfg["cache"].as<std::string>();
  if (cfg["logs"])             s.logs = cfg["logs"].as<std::string>();

  if (cfg["zfs_enable"])       s.zfsEnable = cfg["zfs_enable"].as<bool>();
  if (cfg["zfs_zpool"])        s.zfsZpool = cfg["zfs_zpool"].as<std::string>();
  if (cfg["zfs_options"])      s.zfsOptions = cfg["zfs_options"].as<std::string>();

  if (cfg["network_interface"]) s.networkInterface = cfg["network_interface"].as<std::string>();
  if (cfg["default_bridge"])    s.defaultBridge = cfg["default_bridge"].as<std::string>();
  if (cfg["static_mac_default"]) s.staticMacDefault = cfg["static_mac_default"].as<bool>();

  if (cfg["bootstrap_method"]) s.bootstrapMethod = cfg["bootstrap_method"].as<std::string>();

  if (cfg["securelevel"])      s.securelevel = cfg["securelevel"].as<int>();
  if (cfg["children_max"])     s.childrenMax = cfg["children_max"].as<int>();

  if (cfg["search_path"] && cfg["search_path"].IsSequence()) {
    s.searchPath.clear();
    for (auto &p : cfg["search_path"])
      s.searchPath.push_back(p.as<std::string>());
  }

  if (cfg["compress_xz_options"]) s.compressXzOptions = cfg["compress_xz_options"].as<std::string>();

  // Named networks: map of name -> network definition
  if (cfg["networks"] && cfg["networks"].IsMap()) {
    for (auto net : cfg["networks"]) {
      auto name = net.first.as<std::string>();
      if (!net.second.IsMap())
        continue;
      NetworkDef def;
      auto &n = net.second;
      if (n["mode"])       def.mode = n["mode"].as<std::string>();
      if (n["bridge"])     def.bridge = n["bridge"].as<std::string>();
      if (n["interface"])  def.interface = n["interface"].as<std::string>();
      if (n["gateway"])    def.gateway = n["gateway"].as<std::string>();
      if (n["vlan"])       def.vlan = n["vlan"].as<int>();
      if (n["static-mac"]) def.staticMac = n["static-mac"].as<bool>();
      if (n["ip6"])        def.ip6 = n["ip6"].as<std::string>();
      s.networks[name] = std::move(def);
    }
  }
}

const Settings& load() {
  g_settings = defaults();

  // Load system-wide config
  const char *sysConfig = "/usr/local/etc/crate.yml";
  if (Util::Fs::fileExists(sysConfig)) {
    try {
      auto cfg = YAML::LoadFile(sysConfig);
      applyYaml(g_settings, cfg);
    } catch (...) {
      // ignore malformed system config
    }
  }

  // Load drop-in config fragments (override system config, alphabetical order)
  const std::string confDir = "/usr/local/etc/crate.d";
  DIR *dir = opendir(confDir.c_str());
  if (dir) {
    std::vector<std::string> fragments;
    struct dirent *ent;
    while ((ent = readdir(dir)) != nullptr) {
      std::string name = ent->d_name;
      if (name.size() > 4 && name.substr(name.size() - 4) == ".yml")
        fragments.push_back(name);
    }
    closedir(dir);
    std::sort(fragments.begin(), fragments.end());
    for (auto &f : fragments) {
      try {
        auto cfg = YAML::LoadFile(STR(confDir << "/" << f));
        applyYaml(g_settings, cfg);
      } catch (...) {
        // ignore malformed fragment
      }
    }
  }

  // Load user config (highest priority, overrides everything)
  auto userConfig = STR(Util::Fs::getUserHomeDir() << "/.config/crate/crate.yml");
  if (Util::Fs::fileExists(userConfig)) {
    try {
      auto cfg = YAML::LoadFile(userConfig);
      applyYaml(g_settings, cfg);
    } catch (...) {
      // ignore malformed user config
    }
  }

  g_loaded = true;
  return g_settings;
}

const Settings& get() {
  if (!g_loaded)
    return load();
  return g_settings;
}

std::string resolveCrateFile(const std::string &name) {
  // If name contains path separator or has .crate extension, try as-is first
  if (name.find('/') != std::string::npos || Util::Fs::fileExists(name))
    return name;

  // Search in configured paths
  auto &settings = get();
  for (auto &dir : settings.searchPath) {
    auto expanded = Util::pathSubstituteVarsInPath(dir);
    auto candidate = STR(expanded << "/" << name);
    if (Util::Fs::fileExists(candidate))
      return candidate;
    // Try with .crate extension
    auto candidateExt = STR(candidate << ".crate");
    if (Util::Fs::fileExists(candidateExt))
      return candidateExt;
  }

  return name; // return original, let caller handle error
}

}
