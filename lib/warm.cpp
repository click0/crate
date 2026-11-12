// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// `crate template warm <jail> --output <dataset>` — capture the
// on-disk state of a running jail as a ZFS clone the operator can
// later pass to `crate run --warm-base <dataset>` (planned for
// 0.7.6) to skip cold-create work like pkg install or profile
// init. See lib/warm_pure.h for the scope discussion (memory
// snapshot is intentionally NOT in scope — that needs CRIU/bhyve).
//

#include "args.h"
#include "commands.h"
#include "jail_query.h"
#include "util.h"
#include "warm_pure.h"
#include "warm_trust.h"      // 1.1.75
#include "cmd.h"
#include "crypto_pure.h"
#include "import_pure.h"
#include "pathnames.h"
#include "run_pure.h"
#include "spec_registry.h"
#include "err.h"

#include <rang.hpp>

#include <ctime>
#include <iostream>
#include <sstream>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define ERR(msg...) ERR2("template warm", msg)

// --- 1.1.75: the trusted spec store (warm_trust.h) ---

namespace WarmTrust {

std::string datasetGuid(const std::string &dataset) {
  auto out = Util::stripTrailingSpace(
    Util::execCommandGetOutput(WarmPure::buildGuidArgv(dataset), "zfs get guid"));
  if (WarmPure::trustedSpecPath(out).empty())
    ERR("zfs get guid " << dataset << ": unexpected answer '" << out << "'")
  return out;
}

static std::string archiveMember(const std::string &crateFile, const std::string &name, bool &found) {
  const std::vector<std::string> unxz = {CRATE_PATH_XZ, Cmd::xzThreadsArg, "--decompress"};
  auto listing = Util::execPipelineGetOutput({unxz, {CRATE_PATH_TAR, "tf", "-"}},
                                             "list the crate archive", crateFile);
  std::istringstream is(listing);
  std::string entry;
  while (std::getline(is, entry))
    if (ImportPure::normalizeArchiveEntry(entry) == name) {
      found = true;
      return Util::execPipelineGetOutput({unxz, {CRATE_PATH_TAR, "xOf", "-", entry}},
                                         "read " + name + " from the crate archive", crateFile);
    }
  found = false;
  return "";
}

Spec fromArchive(const std::string &crateFile) {
  if (!Util::Fs::fileExists(crateFile))
    ERR("the crate file " << crateFile << " does not exist")
  if (CryptoPure::detectFile(crateFile) == CryptoPure::Format::Encrypted)
    ERR(crateFile << " is encrypted; decrypt it first (crate run reads plain archives only)")
  Spec s;
  bool found = false;
  s.spec = archiveMember(crateFile, "+CRATE.SPEC", found);
  if (!found || s.spec.empty())
    ERR(crateFile << " has no +CRATE.SPEC — not a crate archive")
  s.thin = archiveMember(crateFile, "+CRATE.THIN", s.haveThin);
  return s;
}

// The store directory, created root-only; refuses a symlink or a
// directory another user owns.
static void ensureStoreDir() {
  for (const std::string &dir : {std::string("/var/db/crate"), WarmPure::trustedStoreDir()}) {
    if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST)
      ERR("mkdir " << dir << ": " << strerror(errno))
    struct stat st;
    if (::lstat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022))
      ERR(dir << " must be a directory owned by root and not writable by others")
  }
}

static bool readStoreFile(const std::string &path, std::string &out) {
  int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return false;
  struct stat st;
  if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0) { ::close(fd); return false; }
  out.clear();
  char buf[8192];
  ssize_t n;
  while ((n = ::read(fd, buf, sizeof(buf))) > 0) out.append(buf, (size_t)n);
  ::close(fd);
  return n == 0;
}

static void writeStoreFile(const std::string &path, const std::string &content) {
  const std::string tmp = path + ".tmp";
  ::unlink(tmp.c_str());
  int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) ERR("create " << tmp << ": " << strerror(errno))
  size_t off = 0;
  while (off < content.size()) {
    ssize_t n = ::write(fd, content.data() + off, content.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      const int e = errno;
      ::close(fd); ::unlink(tmp.c_str());
      ERR("write " << tmp << ": " << strerror(e))
    }
    off += (size_t)n;
  }
  if (::fsync(fd) != 0 || ::close(fd) != 0) { ::unlink(tmp.c_str()); ERR("write " << tmp << ": " << strerror(errno)) }
  if (::rename(tmp.c_str(), path.c_str()) != 0) { ::unlink(tmp.c_str()); ERR("rename " << tmp << ": " << strerror(errno)) }
}

bool fromStore(const std::string &guid, Spec &out) {
  const auto specPath = WarmPure::trustedSpecPath(guid);
  if (specPath.empty() || !readStoreFile(specPath, out.spec)) return false;
  out.haveThin = readStoreFile(WarmPure::trustedThinPath(guid), out.thin);
  return true;
}

void toStore(const std::string &guid, const Spec &s) {
  const auto specPath = WarmPure::trustedSpecPath(guid), thinPath = WarmPure::trustedThinPath(guid);
  if (specPath.empty()) ERR("invalid dataset guid '" << guid << "'")
  ensureStoreDir();
  if (s.haveThin) writeStoreFile(thinPath, s.thin);
  else if (::unlink(thinPath.c_str()) != 0 && errno != ENOENT)
    ERR("unlink " << thinPath << ": " << strerror(errno))
  writeStoreFile(specPath, s.spec);
}

void storePathsFor(const std::string &dataset, std::string &specPath, std::string &thinPath) {
  const auto guid = datasetGuid(dataset);
  Spec probe;
  if (!fromStore(guid, probe))
    ERR2("run", "--warm-base " << dataset << ": the template has no trusted spec in "
         << WarmPure::trustedStoreDir() << " — +CRATE.SPEC inside it may have been rewritten by "
         "the jail it was taken from, and is not used since 1.1.75. If you know which .crate the "
         "template came from: crate template trust " << dataset << " --spec <file.crate>")
  specPath = WarmPure::trustedSpecPath(guid);
  thinPath = probe.haveThin ? WarmPure::trustedThinPath(guid) : std::string();
}

} // namespace WarmTrust

// 1.1.75: `crate template trust <dataset> --spec <file.crate>` — record
// the spec a template made before 1.1.75 (or by hand) runs with.
static bool templateTrustCommand(const Args &args) {
  if (::geteuid() != 0)
    ERR("'template trust' writes " << WarmPure::trustedStoreDir() << " and needs root")
  if (auto e = WarmPure::validateTemplateDataset(args.warmTarget); !e.empty())
    ERR("dataset: " << e)
  auto trusted = WarmTrust::fromArchive(args.warmSpecFile);
  auto guid = WarmTrust::datasetGuid(args.warmTarget);
  WarmTrust::toStore(guid, trusted);
  std::cout << rang::fg::green << "template trust: " << args.warmTarget << " runs with the spec of "
            << args.warmSpecFile << (trusted.haveThin ? " (thin jail)" : "")
            << rang::style::reset << std::endl;
  return true;
}

bool templateWarmCommand(const Args &args) {
  if (args.templateSubcmd == "trust")
    return templateTrustCommand(args);
  if (::geteuid() != 0)   // 1.1.75: zfs snapshot/clone and the trusted store
    ERR("'template warm' needs root")
  if (args.warmTarget.empty())
    ERR("the 'template warm' command requires a jail name (positional arg)")
  if (args.warmOutputDataset.empty())
    ERR("the 'template warm' command requires --output <dataset>")
  if (auto e = WarmPure::validateTemplateDataset(args.warmOutputDataset);
      !e.empty())
    ERR("--output: " << e)

  auto jail = JailQuery::findContainer(args.warmTarget);   // 1.1.70
  if (!jail) ERR("jail '" << args.warmTarget << "' not found or not running")
  if (!Util::Fs::isOnZfs(jail->path))
    ERR("jail '" << args.warmTarget << "' is not on ZFS — warm templates require ZFS")
  // 1.1.72: the jail's own dataset, not the one its directory lies in
  // (that cloned — and with --promote re-parented — the host's root).
  auto sourceDataset = Util::Fs::getZfsDatasetMountedAt(jail->path);
  if (sourceDataset.empty())
    ERR("jail '" << args.warmTarget << "' has no ZFS dataset of its own: " << jail->path
        << " is a directory in " << Util::Fs::getZfsDataset(jail->path)
        << " — a warm template needs a jail that runs from a dataset of its own (a plain "
        "`crate run` does not get one yet)")

  // 1.1.75: the spec the template will run with, from outside the jail's
  // tree, before anything is snapshotted: --spec, else the .crate the
  // jail was started from (the spec registry), else the base template's
  // store entry for a --warm-base run.
  WarmTrust::Spec trusted;
  std::string trustedFrom;
  if (!args.warmSpecFile.empty()) {
    trusted = WarmTrust::fromArchive(args.warmSpecFile);
    trustedFrom = args.warmSpecFile;
  } else {
    const auto container = RunPure::containerNameOfJail(jail->name, jail->path);
    SpecRegistryPure::Entry e;
    if (!SpecRegistry::lookupEntry(container, e))
      ERR("'" << container << "' is not in the spec registry, so the .crate it was started from is "
          "unknown; pass --spec <file.crate> (its +CRATE.SPEC inside the jail is not trusted)")
    if (!e.cratePath.empty()) {
      trusted = WarmTrust::fromArchive(e.cratePath);
      trustedFrom = e.cratePath;
    } else {
      if (!WarmTrust::fromStore(WarmTrust::datasetGuid(e.warmBase), trusted))
        ERR("'" << container << "' runs from the template " << e.warmBase << ", which has no trusted "
            "spec; `crate template trust " << e.warmBase << " --spec <file.crate>` first, or pass --spec")
      trustedFrom = "template " + e.warmBase;
    }
  }

  auto suffix = WarmPure::warmSnapshotSuffix(::time(nullptr));

  std::cerr << rang::fg::cyan
            << "template warm: snapshotting " << sourceDataset
            << "@" << suffix
            << rang::style::reset << std::endl;
  Util::execCommand(WarmPure::buildSnapshotArgv(sourceDataset, suffix),
                    "zfs snapshot");

  std::cerr << rang::fg::cyan
            << "template warm: cloning into " << args.warmOutputDataset
            << rang::style::reset << std::endl;
  // 1.1.69: a failed clone (target exists, parent missing, quota) left
  // the @warm-<ts> snapshot behind on the source jail's dataset.
  try {
    Util::execCommand(
      WarmPure::buildCloneArgv(sourceDataset, suffix, args.warmOutputDataset),
      "zfs clone");
  } catch (...) {
    try { Util::execCommand({CRATE_PATH_ZFS, "destroy", sourceDataset + "@" + suffix}, "zfs destroy snapshot"); }
    catch (...) {}
    throw;
  }

  // Optional promotion — only when the operator asks for it.
  // Default keeps the clone graph intact so retention pruning of
  // old warm snapshots is independent of template usage.
  if (args.warmPromote) {
    std::cerr << rang::fg::cyan
              << "template warm: promoting clone to break parent link"
              << rang::style::reset << std::endl;
    Util::execCommand(
      WarmPure::buildPromoteArgv(args.warmOutputDataset),
      "zfs promote");
  }

  // 1.1.75: record the trusted spec under the template's guid
  try {
    WarmTrust::toStore(WarmTrust::datasetGuid(args.warmOutputDataset), trusted);
  } catch (const std::exception &e) {
    ERR("the template " << args.warmOutputDataset << " was made, but its trusted spec could not be "
        "recorded (" << e.what() << "); `crate template trust " << args.warmOutputDataset
        << " --spec <file.crate>` before running it")
  }
  std::cout << rang::fg::green
            << "template warm: " << args.warmTarget
            << " -> " << args.warmOutputDataset
            << " (snapshot " << suffix << "; spec from " << trustedFrom << ")"
            << rang::style::reset << std::endl;
  return true;
}
