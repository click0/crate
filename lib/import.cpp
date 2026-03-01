// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "pathnames.h"
#include "cmd.h"
#include "locs.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <fstream>

#define ERR(msg...) \
  ERR2("import", msg)

static uid_t myuid = ::getuid();
static gid_t mygid = ::getgid();

// Validate SHA256 checksum if .sha256 file exists alongside the archive
static bool validateChecksum(const std::string &archivePath, bool force) {
  auto sha256File = archivePath + ".sha256";
  if (!Util::Fs::fileExists(sha256File)) {
    if (!force) {
      std::cerr << rang::fg::yellow << "WARNING: no checksum file found (" << sha256File << ")"
                << rang::style::reset << std::endl;
      std::cerr << rang::fg::yellow << "  Use --force to skip checksum validation"
                << rang::style::reset << std::endl;
    }
    return true;  // no checksum file = skip validation (with warning)
  }

  // Read expected checksum from file
  std::ifstream ifs(sha256File);
  if (!ifs.good())
    ERR("cannot read checksum file: " << sha256File)
  std::string line;
  std::getline(ifs, line);
  // Format: "hexhash  filename" or just "hexhash"
  auto spacePos = line.find(' ');
  auto expectedHash = (spacePos != std::string::npos) ? line.substr(0, spacePos) : line;
  expectedHash = Util::stripTrailingSpace(expectedHash);

  // Compute actual checksum
  auto actualOutput = Util::execCommandGetOutput(
    {"/sbin/sha256", "-q", archivePath},
    "compute SHA256 checksum for validation");
  auto actualHash = Util::stripTrailingSpace(actualOutput);

  if (actualHash != expectedHash) {
    std::cerr << rang::fg::red << "Checksum mismatch!" << rang::style::reset << std::endl;
    std::cerr << "  Expected: " << expectedHash << std::endl;
    std::cerr << "  Actual:   " << actualHash << std::endl;
    if (force) {
      std::cerr << rang::fg::yellow << "  --force: proceeding despite mismatch"
                << rang::style::reset << std::endl;
      return true;
    }
    return false;
  }

  std::cout << "Checksum verified: " << actualHash << std::endl;
  return true;
}

// Validate the archive for directory traversal attacks
static void validateArchive(const std::string &archivePath) {
  auto listing = Util::execPipelineGetOutput(
    {{CRATE_PATH_XZ, Cmd::xzThreadsArg, "--decompress"},
     {CRATE_PATH_TAR, "tf", "-"}},
    "list archive contents for validation", archivePath);

  std::istringstream is(listing);
  std::string entry;
  while (std::getline(is, entry)) {
    if (entry.find("..") != std::string::npos)
      ERR("archive contains path with '..' component: " << entry
          << " — refusing to import (directory traversal)")
  }
}

// Inspect the +CRATE.SPEC inside the archive without full extraction
static bool archiveHasSpec(const std::string &archivePath) {
  auto listing = Util::execPipelineGetOutput(
    {{CRATE_PATH_XZ, Cmd::xzThreadsArg, "--decompress"},
     {CRATE_PATH_TAR, "tf", "-"}},
    "list archive contents", archivePath);

  std::istringstream is(listing);
  std::string entry;
  while (std::getline(is, entry)) {
    // Strip leading "./" if present
    auto name = entry;
    if (name.substr(0, 2) == "./") name = name.substr(2);
    // Strip trailing "/"
    while (!name.empty() && name.back() == '/') name.pop_back();
    if (name == "+CRATE.SPEC")
      return true;
  }
  return false;
}

// Check the OS version in +CRATE.OSVERSION
static void checkOsVersion(const std::string &archivePath) {
  // Try to extract +CRATE.OSVERSION from the archive
  try {
    auto output = Util::execPipelineGetOutput(
      {{CRATE_PATH_XZ, Cmd::xzThreadsArg, "--decompress"},
       {CRATE_PATH_TAR, "xf", "-", "-O", "+CRATE.OSVERSION"}},
      "extract OS version from archive", archivePath);
    auto ver = Util::stripTrailingSpace(output);
    if (!ver.empty()) {
      auto hostVer = Util::getFreeBSDMajorVersion();
      auto crateVer = std::stoi(ver);
      if (crateVer != hostVer)
        std::cerr << rang::fg::yellow << "WARNING: crate was built on FreeBSD "
                  << crateVer << " but host is FreeBSD " << hostVer
                  << " — ABI incompatibility possible"
                  << rang::style::reset << std::endl;
    }
  } catch (...) {
    // +CRATE.OSVERSION may not exist in older crate archives — not an error
  }
}

bool importCrate(const Args &args) {
  auto &archivePath = args.importFile;

  // Validate the archive file exists
  if (!Util::Fs::fileExists(archivePath))
    ERR("archive file not found: " << archivePath)

  // Validate file is a valid xz archive
  if (!Util::Fs::isXzArchive(archivePath.c_str()))
    ERR("file is not a valid xz archive: " << archivePath)

  // Determine output filename
  std::string outFile;
  if (!args.importOutput.empty()) {
    outFile = args.importOutput;
  } else {
    // Use the input filename if it already ends in .crate, otherwise add .crate
    outFile = archivePath;
    if (!Util::Fs::hasExtension(archivePath.c_str(), ".crate")) {
      // Strip any existing extension and add .crate
      auto dot = archivePath.rfind('.');
      auto slash = archivePath.rfind('/');
      if (dot != std::string::npos && (slash == std::string::npos || dot > slash))
        outFile = archivePath.substr(0, dot) + ".crate";
      else
        outFile = archivePath + ".crate";
    }
  }

  std::cout << "Importing " << archivePath << " ..." << std::endl;

  // Step 1: Validate checksum
  if (!validateChecksum(archivePath, args.importForce))
    ERR("checksum validation failed — use --force to override")

  // Step 2: Validate archive contents (no directory traversal)
  std::cout << "  Validating archive integrity ..." << std::endl;
  validateArchive(archivePath);

  // Step 3: Check if the archive contains +CRATE.SPEC
  bool hasSpec = archiveHasSpec(archivePath);
  if (!hasSpec) {
    std::cerr << rang::fg::yellow
              << "WARNING: archive does not contain +CRATE.SPEC — this is not a crate archive"
              << rang::style::reset << std::endl;
    if (!args.importForce)
      ERR("refusing to import non-crate archive without --force")
    std::cerr << rang::fg::yellow << "  --force: proceeding without spec"
              << rang::style::reset << std::endl;
  }

  // Step 4: Check OS version compatibility
  checkOsVersion(archivePath);

  // Step 5: If the input file is already a .crate and output == input, just validate
  if (outFile == archivePath) {
    std::cout << rang::fg::green << "Validated: " << archivePath
              << rang::style::reset << std::endl;
    if (hasSpec)
      std::cout << "  Contains +CRATE.SPEC: yes" << std::endl;
    return true;
  }

  // Step 6: Copy/re-compress the archive to the output location
  // If the input is already a valid .crate (tar.xz), just copy it
  Util::Fs::copyFile(archivePath, outFile);
  Util::Fs::chown(outFile, myuid, mygid);

  // Generate checksum for the output file
  auto sha256File = outFile + ".sha256";
  auto checksumOutput = Util::execCommandGetOutput(
    {"/sbin/sha256", "-q", outFile},
    "compute SHA256 checksum of imported crate");
  auto checksum = Util::stripTrailingSpace(checksumOutput);
  Util::Fs::writeFile(STR(checksum << "  " << Util::filePathToFileName(outFile) << "\n"), sha256File);
  Util::Fs::chown(sha256File, myuid, mygid);

  // Report
  struct stat st;
  if (::stat(outFile.c_str(), &st) == 0) {
    double sizeMB = static_cast<double>(st.st_size) / (1024.0 * 1024.0);
    std::cout << rang::fg::green << "Imported: " << outFile
              << " (" << std::fixed << std::setprecision(1) << sizeMB << " MB)"
              << rang::style::reset << std::endl;
  } else {
    std::cout << rang::fg::green << "Imported: " << outFile << rang::style::reset << std::endl;
  }

  return true;
}
