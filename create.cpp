// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include "args.h"
#include "spec.h"
#include "locs.h"
#include "cmd.h"
#include "mount.h"
#include "scripts.h"
#include "util.h"
#include "err.h"
#include "commands.h"

#include <rang.hpp>

#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <functional>
#include <filesystem>

#define ERR(msg...) ERR2("creating a crate", msg)

#define LOG(msg...) \
  { \
    if (args.logProgress) \
      std::cerr << rang::fg::gray << Util::tmSecMs() << ": " << msg << rang::style::reset << std::endl; \
  }

// uid/gid
static uid_t myuid = ::getuid();
static gid_t mygid = ::getgid();

//
// helpers
//

static std::string guessCrateName(const Spec &spec) {
  if (!spec.runCmdExecutable.empty())
    return spec.runCmdExecutable.substr(spec.runCmdExecutable.rfind('/') + 1);
  else {
    std::ostringstream ss;
    ss << *spec.runServices.rbegin();
    for (auto it = spec.runServices.rbegin() + 1; it != spec.runServices.rend(); it++)
      ss << '+' << *it;
    return ss.str();
  }
}

static void notifyUserOfLongProcess(bool begin, const std::string &processName, const std::string &doingWhat) {
  std::cout << rang::fg::blue;
  std::cout << "==" << std::endl;
  if (begin)
    std::cout << "== Running " << processName << " in order to " << doingWhat << std::endl;
  else
    std::cout << "== " << processName << " has finished to " << doingWhat << std::endl;
  std::cout << "==" << rang::fg::reset << std::endl;
}

// exec-based chroot: for pkg commands and similar (argv array, no shell)
static void runChrootCommand(const std::string &jailPath, const std::vector<std::string> &argv,
                             const char *descr, const std::string &stdoutFile = "") {
  auto fullArgv = std::vector<std::string>{"/usr/sbin/chroot", jailPath, "/usr/bin/env", "ASSUME_ALWAYS_YES=yes"};
  fullArgv.insert(fullArgv.end(), argv.begin(), argv.end());
  if (stdoutFile.empty())
    Util::execCommand(fullArgv, descr);
  else
    Util::execPipeline({fullArgv}, descr, "", stdoutFile);
}

// exec-based chroot with shell: for user scripts that need /bin/sh -c
static void runChrootScript(const std::string &jailPath, const std::string &cmd, const char *descr) {
  Util::execCommand({"/usr/sbin/chroot", jailPath, "/bin/sh", "-c",
                     STR("ASSUME_ALWAYS_YES=yes " << cmd)}, descr);
}

static void installAndAddPackagesInJail(const std::string &jailPath,
                                        const std::vector<std::string> &pkgsInstall,
                                        const std::vector<std::string> &pkgsAdd,
                                        const std::vector<std::pair<std::string, std::string>> &pkgLocalOverride,
                                        const std::vector<std::string> &pkgNuke) {
  // local helpers
  auto J = [&jailPath](auto subdir) {
    return STR(jailPath << subdir);
  };

  // notify
  notifyUserOfLongProcess(true, "pkg", STR("install the required packages: " << (pkgsInstall+pkgsAdd)));

  // install
  if (!pkgsInstall.empty()) {
    auto argv = std::vector<std::string>{"pkg", "install"};
    argv.insert(argv.end(), pkgsInstall.begin(), pkgsInstall.end());
    runChrootCommand(jailPath, argv, "install the requested packages into the jail");
  }
  if (!pkgsAdd.empty()) {
    for (auto &p : pkgsAdd) {
      Util::Fs::copyFile(p, STR(J("/tmp/") << Util::filePathToFileName(p)));
      runChrootCommand(jailPath, {"pkg", "add", STR("/tmp/" << Util::filePathToFileName(p))},
                       "add the package file in jail");
    }
  }

  // override packages with locally available packages
  for (auto lo : pkgLocalOverride) {
    if (!Util::Fs::fileExists(lo.second))
      ERR("package override: failed to find the package file '" << lo.second << "'")
    runChrootCommand(jailPath, {"pkg", "delete", lo.first},
                     CSTR("remove the package '" << lo.first << "' for local override in jail"));
    Util::Fs::copyFile(lo.second, STR(J("/tmp/") << Util::filePathToFileName(lo.second)));
    runChrootCommand(jailPath, {"pkg", "add", STR("/tmp/" << Util::filePathToFileName(lo.second))},
                     CSTR("add the local override package '" << lo.second << "' in jail"));
    Util::Fs::unlink(J(STR("/tmp/" << Util::filePathToFileName(lo.second))));
  }

  // nuke packages when requested
  for (auto &n : pkgNuke)
    runChrootCommand(jailPath, {"/usr/local/sbin/pkg-static", "delete", "-y", "-f", n},
                     "nuke the package in the jail");

  // write the +CRATE.PKGS file
  runChrootCommand(jailPath, {"pkg", "info"}, "write +CRATE.PKGS file", J("/+CRATE.PKGS"));
  // cleanup: delete the pkg package: it will not be needed any more, and delete the added package files
  runChrootCommand(jailPath, {"pkg", "delete", "-f", "pkg"}, "remove the 'pkg' package from jail");
  if (!pkgsAdd.empty())
    for (const auto &entry : std::filesystem::directory_iterator(STR(jailPath << "/tmp")))
      if (!entry.is_directory())
        Util::Fs::unlink(entry.path());
  // notify
  notifyUserOfLongProcess(false, "pkg", STR("install the required packages: " << (pkgsInstall+pkgsAdd)));
}

static std::set<std::string> getElfDependencies(const std::string &elfPath, const std::string &jailPath,
                                                std::function<bool(const std::string&)> filter = [](const std::string &path) {return true;})
{
  std::set<std::string> dset;
  // Use ldd(1) via exec (no shell) and parse output in C++
  // ldd output format: "  libfoo.so.1 => /usr/lib/libfoo.so.1 (0x...)"
  auto output = Util::execCommandGetOutput(
    {"/usr/sbin/chroot", jailPath, "ldd", elfPath}, "get elf dependencies");
  std::istringstream is(output);
  std::string line;
  while (std::getline(is, line)) {
    auto arrow = line.find("=>");
    if (arrow == std::string::npos) continue;
    auto pathStart = line.find_first_not_of(" \t", arrow + 2);
    if (pathStart == std::string::npos) continue;
    auto pathEnd = line.find_first_of(" \t(", pathStart);
    auto path = (pathEnd != std::string::npos) ? line.substr(pathStart, pathEnd - pathStart) : line.substr(pathStart);
    path = Util::stripTrailingSpace(path);
    if (!path.empty() && filter(path))
      dset.insert(path);
  }
  return dset;
}

static void removeRedundantJailParts(const std::string &jailPath, const Spec &spec) {
  namespace Fs = Util::Fs;

  const char *prefix = "/usr/local";
  const char *prefixSlash = "/usr/local/";
  auto prefixSlashSz = ::strlen(prefixSlash);
  auto jailPathSz = jailPath.size();
  
  // local helpers
  auto J = [&jailPath](auto subdir) {
    return STR(jailPath << subdir);
  };
  auto toJailPath = [J](const std::set<std::string> &in, std::set<std::string> &out) {
    for (auto &p : in)
      out.insert(J(p));
  };
  auto fromJailPath = [&jailPath,jailPathSz](const std::string &file) {
    auto fileCstr = file.c_str();
    assert(::strncmp(jailPath.c_str(), fileCstr, jailPathSz) == 0); // really begins with jailPath
    return fileCstr + jailPathSz;
  };
  auto isBasePath = [prefixSlash,prefixSlashSz](const std::string &path) {
    return ::strncmp(path.c_str(), prefixSlash, prefixSlashSz) != 0;
  };

  // form the 'except' set: it should only contain files in basem and they should begin with jailPath
  std::set<std::string> except;
  auto keepFile = [&except,&jailPath,J,toJailPath](auto &file) { // any file, not just ELF
    except.insert(J(file));
    if (Fs::isElfFileOrDir(J(file)) == 'E')
      toJailPath(getElfDependencies(file, jailPath), except);
  };
  if (!spec.runCmdExecutable.empty()) {
    if (isBasePath(spec.runCmdExecutable))
      except.insert(J(spec.runCmdExecutable));
    if (Fs::isElfFileOrDir(J(spec.runCmdExecutable)) == 'E')
      toJailPath(getElfDependencies(spec.runCmdExecutable, jailPath), except);
  }
  for (auto &file : spec.baseKeep)
    keepFile(file);
  for (auto &fileWildcard : spec.baseKeepWildcard)
    for (auto &file : Util::Fs::expandWildcards(fileWildcard, jailPath))
      keepFile(file);
  if (!spec.runServices.empty()) {
    keepFile("/usr/sbin/service");  // needed to run a service
    keepFile("/bin/cat");           // based on ktrace of 'service {name} start'
    keepFile("/bin/chmod");         // --"--
    keepFile("/usr/bin/env");       // --"--
    keepFile("/bin/kenv");          // --"--
    keepFile("/bin/mkdir");         // --"--
    keepFile("/usr/bin/touch");     // --"--
    keepFile("/usr/bin/procstat");  // --"--
    keepFile("/usr/bin/grep");      // ?? needed?
    keepFile("/sbin/sysctl");       // ??
    keepFile("/usr/bin/limits");    // ??
    keepFile("/usr/bin/sed");       // needed for /etc/rc.d/netif restart
    keepFile("/bin/kenv");          // needed for /etc/rc.d/netif restart
    keepFile("/usr/sbin/daemon");   // services are often run with daemon(8)
    if (spec.runCmdExecutable.empty())
      keepFile("/bin/sleep");       // our idle script runs
  }
  //keepFile("/sbin/rcorder");        // needed for /etc/rc
  //keepFile("/usr/sbin/ip6addrctl"); // needed for /etc/rc
  //keepFile("/usr/sbin/syslogd");    // needed for /etc/rc
  //keepFile("/usr/bin/mktemp");      // needed for /etc/rc
  //keepFile("/sbin/mdmfs");          // needed for /etc/rc
  //keepFile("/bin/chmod");           // needed for /etc/rc
  //keepFile("/usr/bin/find");        // needed for /etc/rc
  //keepFile("/bin/mkdir");           // needed for /etc/rc
  //keepFile("/usr/sbin/utx");        // needed for /etc/rc
  //keepFile("/usr/bin/uname");       // needed for /etc/rc
  //keepFile("/usr/bin/cmp");         // needed for /etc/rc
  //keepFile("/bin/cp");              // needed for /etc/rc
  //keepFile("/bin/chmod");           // needed for /etc/rc
  //keepFile("/bin/rm");              // needed for /etc/rc
  //keepFile("/bin/rmdir");           // needed for /etc/rc
  keepFile("/sbin/sysctl");         // needed for /etc/rc.shutdown
  if (spec.optionExists("net")) {
    keepFile("/sbin/ifconfig");       // needed to set up interfaces
    keepFile("/sbin/route");          // needed to set the default route
    keepFile("/sbin/ipfw");           // needed to set firewall rules
    keepFile("/usr/sbin/service");    // ??? needed for "net"-enabled crates to start the service ???
    keepFile("/sbin/kldstat");        // ??? needed for "net"-enabled crates to start the service ???
    keepFile("/sbin/kldload");        // ??? needed for "net"-enabled crates to start the service ???
  }
  keepFile("/bin/sleep");           // needed for /etc/rc.shutdown
  keepFile("/bin/date");            // needed for /etc/rc.shutdown
  keepFile("/bin/sh"); // (1) allow to create a user in jail, the user has to have the default shell (2) needed to run scrips when they are specified
  keepFile("/usr/bin/env"); // allow to pass environment to jail
  keepFile("/usr/sbin/pw"); // allow to add users in jail
  keepFile("/usr/sbin/pwd_mkdb"); // allow to add users in jail
  keepFile("/usr/libexec/ld-elf.so.1"); // needed to run elf executables

  if (!spec.pkgInstall.empty() || !spec.pkgAdd.empty())
    for (auto &e : Fs::findElfFiles(J(prefix)))
      toJailPath(getElfDependencies(fromJailPath(e), jailPath, [isBasePath](const std::string &path) {return isBasePath(path);}), except);

  // remove items
  Fs::rmdirFlatExcept(J("/bin"), except);
  Fs::rmdirHier(J("/boot"));
  Fs::rmdirHier(J("/etc/periodic"));
  Fs::unlink(J("/usr/lib/include"));
  Fs::rmdirHierExcept(J("/lib"), except);
  Fs::rmdirHierExcept(J("/usr/lib"), except);
  Fs::rmdirHier(J("/usr/lib32"));
  Fs::rmdirHier(J("/usr/include"));
  Fs::rmdirHierExcept(J("/sbin"), except);
  Fs::rmdirHierExcept(J("/usr/bin"), except);
  Fs::rmdirHierExcept(J("/usr/sbin"), except);
  Fs::rmdirHierExcept(J("/usr/libexec"), except);
  Fs::rmdirHier(J("/usr/share/dtrace"));
  Fs::rmdirHier(J("/usr/share/doc"));
  Fs::rmdirHier(J("/usr/share/examples"));
  Fs::rmdirHier(J("/usr/share/bsdconfig"));
  Fs::rmdirHier(J("/usr/share/games"));
  Fs::rmdirHier(J("/usr/share/i18n"));
  Fs::rmdirHier(J("/usr/share/man"));
  Fs::rmdirHier(J("/usr/share/misc"));
  Fs::rmdirHier(J("/usr/share/pc-sysinstall"));
  Fs::rmdirHier(J("/usr/share/openssl"));
  Fs::rmdirHier(J("/usr/tests"));
  Fs::rmdir    (J("/usr/src"));
  Fs::rmdir    (J("/usr/obj"));
  Fs::rmdirHier(J("/var/db/etcupdate"));
  Fs::rmdirFlat(J("/rescue"));
  if (!spec.pkgInstall.empty() || !spec.pkgAdd.empty()) {
    Fs::rmdirFlat(J("/var/cache/pkg"));
    Fs::rmdirFlat(J("/var/db/pkg"));
  }

  // remove static libs if not requested to keep them
  if (!spec.optionExists("no-rm-static-libs"))
    for (auto &entry : std::filesystem::recursive_directory_iterator(jailPath))
      if (entry.is_regular_file() && entry.path().extension() == ".a")
        Fs::unlink(entry.path());
}

//
// interface
//

bool createCrate(const Args &args, const Spec &spec) {
  int res;

  LOG("'create' command is invoked")

  // output crate file name
  auto crateFileName = !args.createOutput.empty() ? args.createOutput : STR(guessCrateName(spec) << ".crate");

  // download the base archive if not yet
  if (!Util::Fs::fileExists(Locations::baseArchive)) {
    std::cout << "downloading base.txz from " << Locations::baseArchiveUrl << " ..." << std::endl;
    Util::execCommand({"fetch", "-o", Locations::baseArchive, Locations::baseArchiveUrl}, "download base.txz");
    std::cout << "base.txz has finished downloading" << std::endl;
  }

  // create the jail directory
  auto jailPath = STR(Locations::jailDirectoryPath << "/chroot-create-" << Util::filePathToBareName(crateFileName) << "-" << Util::randomHex(4));
  res = mkdir(jailPath.c_str(), S_IRUSR|S_IWUSR|S_IXUSR);
  if (res == -1)
    ERR("failed to create the jail directory '" << jailPath << "': " << strerror(errno))

  // log if jail directory is on encrypted ZFS
  if (Util::Fs::isOnZfs(jailPath)) {
    auto dataset = Util::Fs::getZfsDataset(jailPath);
    if (!dataset.empty() && Util::Fs::isZfsEncrypted(dataset))
      LOG("create directory on encrypted ZFS dataset '" << dataset << "'")
  }

  // helper
  auto runScript = [&jailPath,&spec](const char *section) {
    Scripts::section(section, spec.scripts, [&jailPath,section](const std::string &cmd) {
      runChrootScript(jailPath, cmd, CSTR("run script#" << section));
    });
  };

  RunAtEnd destroyJailDir([&jailPath,&args]() {
    // remove the (future) jail directory
    LOG("removing the the jail directory")
    Util::Fs::rmdirHier(jailPath);
  });

  // unpack the base archive
  LOG("unpacking the base archive")
  Util::execPipeline(
    {{"xz", Cmd::xzThreadsArg, "--decompress"}, {"tar", "-xf", "-", "--uname", "", "--gname", "", "-C", jailPath}},
    "unpack the system base into the jail directory", Locations::baseArchive);

  // Record FreeBSD version used to build this container (for version-mismatch detection at run time)
  Util::Fs::writeFile(STR(Util::getFreeBSDMajorVersion() << "\n"), STR(jailPath << "/+CRATE.OSVERSION"));

  runScript("create:start");

  // copy /etc/resolv.conf into the jail directory such that pkg would be able to resolve addresses
  Util::Fs::copyFile("/etc/resolv.conf", STR(jailPath << "/etc/resolv.conf"));

  // mount devfs (MNT_IGNORE hides it from df/mount output)
  LOG("mounting devfs in jail")
  Mount mountDevfs("devfs", STR(jailPath << "/dev"), "", MNT_IGNORE);
  mountDevfs.mount();

  // mount the pkg cache
  LOG("mounting pkg cache and as nullfs in jail")
  Util::Fs::mkdir(STR(jailPath << "/var/cache/pkg"), 0755);
  Mount mountPkgCache("nullfs", STR(jailPath << "/var/cache/pkg"), "/var/cache/pkg", MNT_IGNORE);
  mountPkgCache.mount();

  // install packages into the jail, if needed
  if (!spec.pkgInstall.empty() || !spec.pkgAdd.empty()) {
    LOG("installing packages ...")
    installAndAddPackagesInJail(jailPath, spec.pkgInstall, spec.pkgAdd, spec.pkgLocalOverride, spec.pkgNuke);
    LOG("done installing packages")
  }

  // unmount
  LOG("unmounting devfs in jail")
  mountDevfs.unmount();
  LOG("unmounting pkg cache in jail")
  mountPkgCache.unmount();

  // remove parts that aren't needed
  LOG("removing unnecessary parts")
  removeRedundantJailParts(jailPath, spec);

  // remove /etc/resolv.conf in the jail directory
  Util::Fs::unlink(STR(jailPath << "/etc/resolv.conf"));

  // write the +CRATE-SPEC file
  LOG("write the +CRATE.SPEC file")
  Util::Fs::copyFile(args.createSpec, STR(jailPath << "/+CRATE.SPEC"));

  // scripts: end-create
  runScript("create:end");

  // pack the jail into a .crate file
  LOG("creating the crate file " << crateFileName)
  Util::execPipeline(
    {{"tar", "cf", "-", "-C", jailPath, "."}, {"xz", Cmd::xzThreadsArg, "--extreme"}},
    "compress the jail directory into the crate file", "", crateFileName);
  Util::Fs::chown(crateFileName, myuid, mygid);

  // remove the create directory
  destroyJailDir.doNow();

  // finished
  std::cout << "the crate file '" << crateFileName << "' has been created" << std::endl;
  LOG("'create' command has succeeded")
  return true;
}
