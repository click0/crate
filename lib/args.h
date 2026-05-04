// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

#include <string>
#include <vector>
#include <map>

enum Command {CmdNone, CmdCreate, CmdRun, CmdValidate, CmdSnapshot, CmdExport, CmdImport, CmdGui, CmdList, CmdInfo, CmdClean, CmdConsole, CmdStack, CmdStats, CmdLogs, CmdStop, CmdRestart, CmdTop, CmdInterDns, CmdVpn, CmdInspect, CmdMigrate, CmdBackup, CmdRestore, CmdReplicate, CmdTemplate, CmdRetune, CmdThrottle};

class Args {
public:
  Args() : logProgress (false) { }

  Command cmd;

  // general params
  bool logProgress; // log progress
  bool noColor = false;  // --no-color: disable colored output (also honors NO_COLOR env)

  // variable substitution: --var KEY=VALUE replaces ${KEY} in spec YAML
  std::map<std::string, std::string> vars;

  // create parameters
  std::string createSpec;
  std::string createOutput;
  std::string createTemplate;  // --template name or path
  bool usePkgbase = false;     // --use-pkgbase: bootstrap jail via pkgbase instead of base.txz

  // run parameters
  std::string runCrateFile;

  // validate parameters
  std::string validateSpec;

  // snapshot parameters
  std::string snapshotSubcmd;   // "create", "list", "restore", "delete", "diff"
  std::string snapshotDataset;  // ZFS dataset name
  std::string snapshotName;     // snapshot name (for create/restore/delete)
  std::string snapshotName2;    // second snapshot name (for diff)

  // list parameters
  bool listJson = false;        // -j: output as JSON

  // info parameters
  std::string infoTarget;       // jail name or JID

  // clean parameters
  bool cleanDryRun = false;     // -n/--dry-run: show what would be cleaned

  // export parameters
  std::string exportTarget;     // container name or JID
  std::string exportOutput;     // -o/--output: output file path
  std::string exportPassphraseFile; // -P/--passphrase-file: encrypt with passphrase from file
  std::string exportSignKey;    // -K/--sign-key: ed25519 secret key for .sig sidecar

  // import parameters
  std::string importFile;       // archive file to import
  std::string importOutput;     // -o/--output: output directory
  bool importForce = false;     // -f/--force: skip checksum verification
  std::string importPassphraseFile; // -P/--passphrase-file: decrypt with passphrase from file
  std::string importVerifyKey;  // -V/--verify-key: ed25519 public key; required if .sig sidecar present

  // console parameters
  std::string consoleTarget;    // jail name or JID
  std::string consoleUser;      // -u/--user: user to login as
  std::string consoleCmd;       // optional command to run

  // gui parameters
  std::string guiSubcmd;        // "list", "focus", "attach", "url", "tile", "screenshot", "resize"
  std::string guiTarget;        // container name, JID, or display number
  std::string guiOutput;        // -o/--output: output file (for screenshot)
  std::string guiResolution;    // WxH (for resize)
  bool guiJson = false;         // -j: output as JSON (for gui list)

  // stack parameters
  std::string stackSubcmd;      // "up", "down", "status", "exec"
  std::string stackFile;        // stack YAML file path
  std::string stackExecContainer; // container name for "exec" subcommand
  std::vector<std::string> stackExecArgs; // command args for "exec" subcommand

  // stats parameters
  std::string statsTarget;      // jail name or JID
  bool statsJson = false;       // -j: output as JSON

  // logs parameters
  std::string logsTarget;       // jail name or JID
  bool logsFollow = false;      // -f/--follow: stream logs
  unsigned logsTail = 0;        // --tail N: show last N lines (0=all)

  // stop parameters
  std::string stopTarget;       // jail name or JID
  unsigned stopTimeout = 10;    // -t/--timeout: seconds before SIGKILL

  // restart parameters
  std::string restartTarget;    // jail name or JID
  unsigned restartTimeout = 10; // -t/--timeout: stop timeout before restart

  // vpn parameters
  std::string vpnSubcmd;        // "wireguard"
  std::string vpnAction;        // "render-conf"
  std::string vpnSpecFile;      // YAML spec file with [Interface]/[Peer] data

  // inspect parameters
  std::string inspectTarget;    // jail name or JID

  // migrate parameters
  std::string migrateTarget;        // container name on both ends
  std::string migrateFrom;          // source crated endpoint host:port
  std::string migrateTo;            // destination crated endpoint host:port
  std::string migrateFromTokenFile; // chmod-600 file with source admin token
  std::string migrateToTokenFile;   // chmod-600 file with destination admin token

  // backup parameters
  std::string backupTarget;            // jail name
  std::string backupOutputDir;         // absolute dir for the .zstream
  std::string backupSince;             // optional explicit --since snapshot suffix
  bool        backupAutoIncremental = false; // --auto-incremental: use latest backup-* if any

  // restore parameters
  std::string restoreFile;             // path to .zstream
  std::string restoreDataset;          // ZFS dest dataset (pool/jails/name)

  // replicate parameters
  std::string replicateTarget;         // jail name (positional)
  std::string replicateTo;             // user@host or host (--to)
  std::string replicateDestDataset;    // pool/jails/name on remote (--dest-dataset)
  std::string replicateSince;          // explicit --since snapshot suffix
  bool        replicateAutoIncremental = false; // --auto-incremental
  unsigned    replicateSshPort = 0;    // --ssh-port (0 = ssh default)
  std::string replicateSshKey;         // --ssh-key /path/to/identity
  std::string replicateSshConfig;      // --ssh-config /path/to/ssh_config
  std::vector<std::string> replicateSshOpts; // repeatable --ssh-opt KEY=VAL

  // template parameters (subcommand: "warm")
  std::string templateSubcmd;       // currently only "warm"
  std::string warmTarget;           // jail name
  std::string warmOutputDataset;    // ZFS dataset to clone into
  bool        warmPromote = false;  // --promote: zfs promote after clone

  // retune parameters
  std::string retuneTarget;             // jail name or JID
  std::vector<std::string> retunePairs; // repeatable --rctl KEY=VALUE
  std::vector<std::string> retuneClear; // repeatable --clear KEY (drops the rule)
  bool        retuneShow = false;       // --show: dump usage before+after

  // throttle parameters (dummynet token-bucket network shaping)
  std::string throttleTarget;        // jail name or JID
  std::string throttleIngressRate;   // --ingress RATE
  std::string throttleIngressBurst;  // --ingress-burst BYTES
  std::string throttleEgressRate;    // --egress RATE
  std::string throttleEgressBurst;   // --egress-burst BYTES
  std::string throttleQueue;         // --queue (slot count or "100KB")
  bool        throttleClear = false; // --clear: drop pipes + binds
  bool        throttleShow = false;  // --show: dump pipe state

  void validate();
};

Args parseArguments(int argc, char** argv, unsigned &processed);
