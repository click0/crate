// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "autoname_pure.h"
#include "jail_query.h"
#include "pathnames.h"
#include "cmd.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <filesystem>

#define ERR(msg...) \
  ERR2("export", msg)

static uid_t myuid = ::getuid();
static gid_t mygid = ::getgid();

// Resolve a running container by name or JID (uses libjail API).
static bool resolveContainer(const std::string &target, int &jid, std::string &path, std::string &hostname) {
  // Try direct lookup
  auto jail = JailQuery::getJailByName(target);
  if (!jail) {
    try {
      int id = std::stoi(target);
      jail = JailQuery::getJailByJid(id);
    } catch (...) {}
  }
  if (jail) {
    jid = jail->jid;
    path = jail->path;
    hostname = jail->hostname;
    return true;
  }

  // Fall back to scanning all jails for partial match
  for (auto &j : JailQuery::getAllJails()) {
    bool match = false;
    if (j.hostname == target) match = true;
    else if (j.name.find("jail-" + target + "-") == 0) match = true;
    if (match) {
      jid = j.jid;
      path = j.path;
      hostname = j.hostname;
      return true;
    }
  }
  return false;
}

// autoExportName moved to lib/autoname_pure.cpp (AutoNamePure::exportName).
static inline std::string autoExportName(const std::string &baseName) {
  return AutoNamePure::exportName(baseName);
}

bool exportCrate(const Args &args) {
  auto &target = args.exportTarget;

  // Resolve the running container
  int jid;
  std::string path, hostname;
  if (!resolveContainer(target, jid, path, hostname))
    ERR("container '" << target << "' not found or not running")

  // Determine output file
  std::string outFile;
  if (!args.exportOutput.empty()) {
    outFile = args.exportOutput;
  } else {
    // Derive name from target or hostname
    auto baseName = hostname.empty() ? target : hostname;
    outFile = autoExportName(baseName);
  }

  // Validate output path: don't overwrite existing file unless explicit
  if (Util::Fs::fileExists(outFile))
    ERR("output file '" << outFile << "' already exists — remove it first or specify a different output with -o")

  std::cout << "Exporting container " << target << " (JID " << jid
            << ") from " << path << " ..." << std::endl;

  // Pack the container's root filesystem into a .crate archive
  // This captures the current state of the running container's filesystem
  Util::execPipeline(
    {{CRATE_PATH_TAR, "cf", "-", "-C", path, "."},
     {CRATE_PATH_XZ, Cmd::xzThreadsArg, "--extreme"}},
    "export container filesystem to crate archive", "", outFile);

  // Set ownership to the calling user
  Util::Fs::chown(outFile, myuid, mygid);

  // Generate SHA256 checksum
  auto sha256File = outFile + ".sha256";
  auto checksumOutput = Util::execCommandGetOutput(
    {"/sbin/sha256", "-q", outFile},
    "compute SHA256 checksum of exported crate");
  auto checksum = Util::stripTrailingSpace(checksumOutput);
  Util::Fs::writeFile(STR(checksum << "  " << Util::filePathToFileName(outFile) << "\n"), sha256File);
  Util::Fs::chown(sha256File, myuid, mygid);

  // Report file size
  struct stat st;
  if (::stat(outFile.c_str(), &st) == 0) {
    double sizeMB = static_cast<double>(st.st_size) / (1024.0 * 1024.0);
    std::cout << rang::fg::green << "Exported: " << outFile
              << " (" << std::fixed << std::setprecision(1) << sizeMB << " MB)"
              << rang::style::reset << std::endl;
    std::cout << "Checksum: " << sha256File << std::endl;
  } else {
    std::cout << rang::fg::green << "Exported: " << outFile << rang::style::reset << std::endl;
  }

  return true;
}
