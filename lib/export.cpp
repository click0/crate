// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
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

// Resolve a running container by name or JID (same logic as info/console)
static bool resolveContainer(const std::string &target, int &jid, std::string &path, std::string &hostname) {
  auto output = Util::execCommandGetOutput(
    {CRATE_PATH_JLS, "-N", "jid", "name", "path", "host.hostname"},
    "list jails for export");
  std::istringstream is(output);
  std::string line;
  while (std::getline(is, line)) {
    if (line.empty() || line[0] == ' ') continue;
    std::istringstream ls(line);
    std::string jidS, name, p, h;
    ls >> jidS >> name >> p >> h;
    if (jidS.empty() || jidS == "jid") continue;

    bool match = false;
    if (name == target || jidS == target)
      match = true;
    else if (h == target)
      match = true;
    else if (name.find("jail-" + target + "-") == 0)
      match = true;

    if (match) {
      jid = std::stoi(jidS);
      path = p;
      hostname = h;
      return true;
    }
  }
  return false;
}

static std::string autoExportName(const std::string &baseName) {
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  std::ostringstream ss;
  ss << baseName << "-" << std::put_time(std::gmtime(&time), "%Y%m%d-%H%M%S") << ".crate";
  return ss.str();
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
