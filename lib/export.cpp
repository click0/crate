// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "autoname_pure.h"
#include "crypto_pure.h"
#include "sign_pure.h"
#include "jail_query.h"
#include "run_pure.h"     // 1.1.77: containerNameOfJail
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
// 1.1.77: findContainer only. The fallback after it matched the hostname
// of ANY jail (by default the host's own, for every one) and bypassed the
// ambiguity refusal; findContainer already takes the "<name>_pid<N>"
// kernel name by its container name.
static bool resolveContainer(const std::string &target, int &jid, std::string &path,
                             std::string &containerName, unsigned &matches) {
  // 1.1.70: kernel name, jid or container name (findContainer)
  auto jail = JailQuery::findContainer(target, &matches);
  if (!jail)
    return false;
  jid = jail->jid;
  path = jail->path;
  containerName = RunPure::containerNameOfJail(jail->name, jail->path);
  return true;
}

// autoExportName moved to lib/autoname_pure.cpp (AutoNamePure::exportName).
static inline std::string autoExportName(const std::string &baseName) {
  return AutoNamePure::exportName(baseName);
}

bool exportCrate(const Args &args) {
  auto &target = args.exportTarget;

  // Resolve the running container
  int jid;
  std::string path, containerName;
  unsigned matches = 0;
  if (!resolveContainer(target, jid, path, containerName, matches)) {
    if (matches > 1)
      ERR("'" << target << "' names " << matches
          << " running jails; give the jail name from `crate list` or its jid")
    ERR("container '" << target << "' not found or not running")
  }

  // Determine output file
  std::string outFile;
  if (!args.exportOutput.empty()) {
    outFile = args.exportOutput;
  } else {
    // 1.1.77: from the container name. The hostname is the jail's to set
    // (allow.set_hostname) and may hold '/', which put the archive in
    // another directory.
    auto baseName = containerName.empty() ? target : containerName;
    outFile = autoExportName(baseName);
  }

  // Validate output path: don't overwrite existing file unless explicit.
  // 1.1.71: lstat — a dangling symlink passed the stat-based check, and
  // root then wrote the archive wherever it pointed.
  {
    struct stat lst;
    if (::lstat(outFile.c_str(), &lst) == 0)
      ERR("output file '" << outFile << "' already exists — remove it first or specify a different output with -o")
  }

  // If a passphrase file was supplied, validate it before doing any work.
  bool encrypt = !args.exportPassphraseFile.empty();
  if (encrypt)
    CryptoPure::validatePassphraseFile(args.exportPassphraseFile);

  std::cout << "Exporting container " << target << " (JID " << jid
            << ") from " << path
            << (encrypt ? " (encrypted)" : "") << " ..." << std::endl;

  // Pack the container's root filesystem into a .crate archive.
  // tar -> xz -> [openssl enc] -> file
  std::vector<std::vector<std::string>> pipeline = {
    // 1.1.48: --one-file-system — everything `crate run` nullfs-mounted
    // into the jail (dirs/share, files/share, X11/Wayland/Pulse sockets)
    // and devfs are separate filesystems; without the flag a spec sharing
    // $HOME exported the operator's home directory into a shareable
    // .crate (and packed /dev nodes). Only the jail's own root goes in.
    {CRATE_PATH_TAR, "cf", "-", "--one-file-system", "-C", path, "."},
    {CRATE_PATH_XZ, Cmd::xzThreadsArg, "--extreme"},
  };
  if (encrypt)
    pipeline.push_back(CryptoPure::buildEncryptArgv(args.exportPassphraseFile));

  // 1.1.71: a new file, 0600, no symlink followed (it was 0644 through
  // whatever sat at the path); a failed pipeline leaves no partial archive.
  try {
    Util::execPipelineToPrivateFile(
      pipeline,
      encrypt ? "export and encrypt container filesystem"
              : "export container filesystem to crate archive",
      outFile);
  } catch (...) {
    struct stat lst;
    if (::lstat(outFile.c_str(), &lst) == 0 && S_ISREG(lst.st_mode) && lst.st_uid == ::geteuid())
      ::unlink(outFile.c_str());
    throw;
  }

  // Set ownership to the calling user
  Util::Fs::chown(outFile, myuid, mygid);

  // Generate SHA256 checksum
  auto sha256File = outFile + ".sha256";
  auto checksumOutput = Util::execCommandGetOutput(
    {CRATE_PATH_SHA256, "-q", outFile},
    "compute SHA256 checksum of exported crate");
  auto checksum = Util::stripTrailingSpace(checksumOutput);
  Util::Fs::writeFile(STR(checksum << "  " << Util::filePathToFileName(outFile) << "\n"), sha256File);
  Util::Fs::chown(sha256File, myuid, mygid);

  // Sign the on-disk archive with ed25519 if requested. The signature
  // covers the encrypted bytes (when -P was used), so the public key
  // can verify provenance without holding the passphrase.
  bool sign = !args.exportSignKey.empty();
  std::string sigFile;
  if (sign) {
    SignPure::validateSecretKeyFile(args.exportSignKey);
    sigFile = SignPure::sidecarPath(outFile);
    Util::execCommand(
      SignPure::buildSignArgv(args.exportSignKey, outFile, sigFile),
      "sign exported crate with ed25519 secret key");
    Util::Fs::chown(sigFile, myuid, mygid);
    Util::Fs::chmod(sigFile, 0644);
  }

  // Report file size
  struct stat st;
  if (::stat(outFile.c_str(), &st) == 0) {
    double sizeMB = static_cast<double>(st.st_size) / (1024.0 * 1024.0);
    std::cout << rang::fg::green << "Exported: " << outFile
              << " (" << std::fixed << std::setprecision(1) << sizeMB << " MB"
              << (encrypt ? ", AES-256-CBC encrypted" : "")
              << (sign ? ", ed25519-signed" : "") << ")"
              << rang::style::reset << std::endl;
    std::cout << "Checksum: " << sha256File << std::endl;
    if (sign)
      std::cout << "Signature: " << sigFile << std::endl;
  } else {
    std::cout << rang::fg::green << "Exported: " << outFile << rang::style::reset << std::endl;
  }

  return true;
}
