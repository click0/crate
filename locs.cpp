// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include "locs.h"
#include "util.h"

#include <string>

namespace Locations {

const char *jailDirectoryPath = "/var/run/crate";
const char *jailSubDirectoryIfaces = "/ifaces";
const char *cacheDirectoryPath = "/var/cache/crate";
const std::string ctxFwUsersFilePath = std::string(jailDirectoryPath) + "/ctx-firewall-users";
const std::string baseArchive = std::string(Locations::cacheDirectoryPath) + "/base.txz";
// Use "releases/" for release versions, "snapshots/" for CURRENT/STABLE
const std::string baseArchiveUrl = STRg("https://download.freebsd.org/"
                                        << (Util::getSysctlString("kern.osrelease").find("-RELEASE") != std::string::npos
                                            ? "releases" : "snapshots")
                                        << "/" << Util::getSysctlString("hw.machine") << "/"
                                        << Util::getSysctlString("kern.osrelease") << "/base.txz");

}
