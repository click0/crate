// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>

class Spec {
public:
  class OptDetails {
  public:
    virtual ~OptDetails() = 0;
  };
  class NetOptDetails : public OptDetails {
  public:
    NetOptDetails();
    static std::shared_ptr<NetOptDetails> createDefault();
    typedef std::pair<unsigned,unsigned> PortRange;
    bool outboundWan;                 // allow outbound connections to WAN
    bool outboundLan;                 // allow outbound connections to LAN
    bool outboundHost;                // allow outbound connections to the host
    bool outboundDns;                 // allow DNS
    std::vector<std::pair<PortRange, PortRange>> inboundPortsTcp;
    std::vector<std::pair<PortRange, PortRange>> inboundPortsUdp;

    bool allowOutbound() const;
    bool allowInbound() const;
  };
  class TorOptDetails : public OptDetails {
  public:
    TorOptDetails();
    static std::shared_ptr<TorOptDetails> createDefault();
    bool controlPort;                 // option to have control port created to be used from inside of the container
  };
  std::vector<std::string>                           baseKeep;
  std::vector<std::string>                           baseKeepWildcard;
  std::vector<std::string>                           baseRemove;

  std::vector<std::string>                           pkgInstall;              // 0..oo packages to install
  std::vector<std::pair<std::string, std::string>>   pkgLocalOverride;        // 0..oo packages to override
  std::vector<std::string>                           pkgAdd;                  // 0..oo packages to add
  std::vector<std::string>                           pkgNuke;                 // 0..oo packages to nuke, i.e. delete without regard of them being nominally used

  std::string                                        runCmdExecutable;        // 0..1 executables can be run
  std::string                                        runCmdArgs;              // can only be set when runCmdExecutable is set, always has a leading space when not blank
  std::vector<std::string>                           runServices;             // 0..oo services can be run

  std::vector<std::pair<std::string, std::string>>   dirsShare;               // any number of directories can be shared, {from -> to} mappings are elements
  std::vector<std::pair<std::string, std::string>>   filesShare;              // any number of files can be shared, {from -> to} mappings are elements

  std::map<std::string, std::shared_ptr<OptDetails>> options;                 // various options that this spec uses

  std::vector<std::string>                           zfsDatasets;             // 0..oo ZFS datasets to attach to jail

  // IPC controls (§7)
  bool                                               allowSysvipc = false;    // allow System V IPC (shared memory, semaphores, message queues)
  bool                                               allowMqueue = false;     // allow POSIX message queues
  bool                                               ipcRawSocketsOverride = false; // if true, override net-based raw_sockets default
  bool                                               ipcRawSocketsValue = false;

  // Resource limits via RCTL (§5)
  std::map<std::string, std::string>                 limits;                  // RCTL resource limits: name -> value

  // Encryption (§1)
  bool                                               encrypted = false;       // require encrypted ZFS dataset
  std::string                                        encryptionMethod;        // "zfs" (default/only)
  std::string                                        encryptionKeyformat;     // "passphrase", "hex", "raw"
  std::string                                        encryptionCipher;        // "aes-256-gcm" (default)

  // DNS filtering (§4)
  struct DnsFilter {
    std::vector<std::string> allow;           // wildcard patterns to allow
    std::vector<std::string> block;           // wildcard patterns to block
    std::string              redirectBlocked;  // IP or "nxdomain"
  };
  std::unique_ptr<DnsFilter>                         dnsFilter;

  // Security hardening (§8)
  int                                                enforceStatfs = -1;      // -1=auto, 0/1/2
  bool                                               allowQuotas = false;
  bool                                               allowSetHostname = false;
  bool                                               allowChflags = false;
  bool                                               allowMlock = false;

  // Copy-on-Write filesystem (§6)
  struct CowOptions {
    std::string mode;     // "ephemeral" or "persistent"
    std::string backend;  // "zfs" (default) or "unionfs"
  };
  std::unique_ptr<CowOptions>                        cowOptions;

  // GUI/Desktop isolation (§11)
  struct X11Options {
    std::string mode = "shared";     // "nested", "shared", "none"
    std::string resolution = "1280x720";
    bool clipboardEnabled = true;
  };
  std::unique_ptr<X11Options>                        x11Options;

  // Clipboard isolation (§12)
  struct ClipboardOptions {
    std::string mode = "shared";     // "isolated", "shared", "none"
    std::string direction = "both";  // "in", "out", "both", "none"
  };
  std::unique_ptr<ClipboardOptions>                  clipboardOptions;

  // D-Bus isolation (§13)
  struct DbusOptions {
    bool systemBus = false;
    bool sessionBus = true;
    std::vector<std::string> allowOwn;
    std::vector<std::string> denySend;
  };
  std::unique_ptr<DbusOptions>                       dbusOptions;

  // Managed services (§14)
  struct ManagedService {
    std::string name;
    bool enable = true;
    std::string rcvar;    // optional rc.conf variable name
  };
  std::vector<ManagedService>                        managedServices;
  bool                                               servicesAutoStart = true;

  // Socket proxy (§15)
  struct SocketProxy {
    std::vector<std::string> share;  // host sockets to share via nullfs
    struct ProxyEntry {
      std::string host;
      std::string jail;
      std::string direction = "bidirectional"; // "bidirectional", "in", "out"
    };
    std::vector<ProxyEntry> proxy;
  };
  std::unique_ptr<SocketProxy>                       socketProxy;

  std::map<std::string, std::map<std::string, std::string>> scripts;          // by section, by script name

  Spec preprocess() const;
  void validate() const;
  bool optionExists(const char* opt) const;
  const NetOptDetails* optionNet() const;
  NetOptDetails* optionNetWr() const;
  const TorOptDetails* optionTor() const;
private:
  template<class OptDetailsClass>
  const OptDetailsClass* getOptionDetails(const char *opt) const;
  template<class OptDetailsClass>
  OptDetailsClass* getOptionDetailsWr(const char *opt) const;
};

Spec parseSpec(const std::string &fname);
