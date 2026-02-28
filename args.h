// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#pragma once

#include <string>

enum Command {CmdNone, CmdCreate, CmdRun, CmdValidate, CmdSnapshot, CmdExport, CmdImport};

class Args {
public:
  Args() : logProgress (false) { }

  Command cmd;

  // general params
  bool logProgress; // log progress
  bool noColor = false;  // --no-color: disable colored output (also honors NO_COLOR env)

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

  // import parameters
  std::string importFile;       // archive file to import
  std::string importOutput;     // -o/--output: output directory
  bool importForce = false;     // -f/--force: skip checksum verification

  // console parameters
  std::string consoleTarget;    // jail name or JID
  std::string consoleUser;      // -u/--user: user to login as
  std::string consoleCmd;       // optional command to run

  void validate();
};

Args parseArguments(int argc, char** argv, unsigned &processed);
