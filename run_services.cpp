// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "run_services.h"
#include "spec.h"
#include "net.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include <iostream>
#include <sstream>
#include <filesystem>

#define ERR(msg...) ERR2("services", msg)

namespace RunServices {

void setupDnsFilter(const Spec &spec, const std::string &jailPath, bool logProgress) {
  if (!spec.dnsFilter)
    return;

  auto J = [&jailPath](auto subdir) { return STR(jailPath << subdir); };

  std::ostringstream conf;
  conf << "server:" << std::endl;
  conf << "  interface: 127.0.0.1" << std::endl;
  conf << "  port: 53" << std::endl;
  conf << "  access-control: 127.0.0.0/8 allow" << std::endl;
  conf << "  do-not-query-localhost: no" << std::endl;
  conf << "  hide-identity: yes" << std::endl;
  conf << "  hide-version: yes" << std::endl;

  auto redirect = spec.dnsFilter->redirectBlocked;
  bool useNxdomain = redirect.empty() || redirect == "nxdomain";
  for (auto &pattern : spec.dnsFilter->block) {
    auto domain = pattern;
    if (domain.size() > 2 && domain.substr(0, 2) == "*.")
      domain = domain.substr(2);
    if (useNxdomain) {
      conf << "  local-zone: \"" << domain << "\" always_nxdomain" << std::endl;
    } else {
      conf << "  local-zone: \"" << domain << "\" redirect" << std::endl;
      conf << "  local-data: \"" << domain << " A " << redirect << "\"" << std::endl;
    }
  }

  auto nameserverIpDns = Net::getNameserverIp();
  conf << "forward-zone:" << std::endl;
  conf << "  name: \".\"" << std::endl;
  conf << "  forward-addr: " << nameserverIpDns << std::endl;

  Util::Fs::mkdir(J("/usr/local/etc/unbound"), 0755);
  Util::Fs::writeFile(conf.str(), J("/usr/local/etc/unbound/unbound.conf"));
  Util::Fs::writeFile("nameserver 127.0.0.1\n", J("/etc/resolv.conf"));

  if (logProgress)
    std::cerr << rang::fg::gray << "DNS filtering configured: " << spec.dnsFilter->block.size()
              << " blocked domains" << rang::style::reset << std::endl;
}

RunAtEnd setupSocketProxy(const Spec &spec, const std::string &jailPath, bool logProgress) {
  if (!spec.socketProxy)
    return RunAtEnd();

  auto J = [&jailPath](auto subdir) { return STR(jailPath << subdir); };

  for (auto &sockPath : spec.socketProxy->share) {
    Util::safePath(sockPath, "/", "shared socket");
    auto parentDir = sockPath.substr(0, sockPath.rfind('/'));
    std::filesystem::create_directories(J(parentDir));
    Util::Fs::writeFile("", J(sockPath));
    // Note: actual nullfs mount must be done by caller since we don't have mount list here
    if (logProgress)
      std::cerr << rang::fg::gray << "shared socket: " << sockPath << rang::style::reset << std::endl;
  }

  std::vector<pid_t> socatPids;
  for (auto &entry : spec.socketProxy->proxy) {
    if (logProgress)
      std::cerr << rang::fg::gray << "starting socket proxy: " << entry.host << " <-> " << entry.jail << rang::style::reset << std::endl;
    auto jailParent = entry.jail.substr(0, entry.jail.rfind('/'));
    std::filesystem::create_directories(J(jailParent));
    pid_t pid = ::fork();
    if (pid == 0) {
      ::execl(CRATE_PATH_SOCAT, "socat",
              STR("UNIX-LISTEN:" << J(entry.jail) << ",fork").c_str(),
              STR("UNIX-CONNECT:" << entry.host).c_str(),
              nullptr);
      ::_exit(127);
    }
    if (pid > 0)
      socatPids.push_back(pid);
  }

  if (socatPids.empty())
    return RunAtEnd();

  return RunAtEnd([socatPids]() {
    for (auto pid : socatPids) {
      ::kill(pid, SIGTERM);
      int status;
      ::waitpid(pid, &status, 0);
    }
  });
}

void setupManagedServices(const Spec &spec, const std::string &jailPath,
                          const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail,
                          bool logProgress) {
  if (spec.managedServices.empty())
    return;

  auto J = [&jailPath](auto subdir) { return STR(jailPath << subdir); };

  std::ostringstream rcConf;
  for (auto &svc : spec.managedServices) {
    auto var = svc.rcvar.empty() ? STR(svc.name << "_enable") : svc.rcvar;
    rcConf << var << "=\"" << (svc.enable ? "YES" : "NO") << "\"" << std::endl;
  }
  Util::Fs::appendFile(rcConf.str(), J("/etc/rc.conf"));

  if (logProgress)
    std::cerr << rang::fg::gray << "managed services: " << spec.managedServices.size()
              << " rc.conf entries generated" << rang::style::reset << std::endl;

  if (spec.servicesAutoStart) {
    for (auto &svc : spec.managedServices) {
      if (svc.enable) {
        if (logProgress)
          std::cerr << rang::fg::gray << "starting managed service: " << svc.name << rang::style::reset << std::endl;
        execInJail({"/usr/sbin/service", svc.name, "onestart"}, CSTR("start managed service " << svc.name));
      }
    }
  }
}

void startServices(const Spec &spec,
                   const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail,
                   const std::function<void(const char*)> &runScript) {
  runScript("run:before-start-services");
  if (!spec.runServices.empty())
    for (auto &service : spec.runServices)
      execInJail({"/usr/sbin/service", service, "onestart"}, "start the service in jail");
  runScript("run:after-start-services");
}

void stopServices(const Spec &spec,
                  const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail) {
  if (!spec.runServices.empty())
    for (auto &service : Util::reverseVector(spec.runServices))
      execInJail({"/usr/sbin/service", service, "onestop"}, "stop the service in jail");
}

void stopManagedServices(const Spec &spec,
                         const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail,
                         bool logProgress) {
  if (spec.managedServices.empty() || !spec.servicesAutoStart)
    return;

  for (auto it = spec.managedServices.rbegin(); it != spec.managedServices.rend(); ++it) {
    if (it->enable) {
      if (logProgress)
        std::cerr << rang::fg::gray << "stopping managed service: " << it->name << rang::style::reset << std::endl;
      execInJail({"/usr/sbin/service", it->name, "onestop"}, CSTR("stop managed service " << it->name));
    }
  }
}

}
