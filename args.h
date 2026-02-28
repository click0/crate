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

  // export parameters
  std::string exportTarget;     // container name or JID to export
  std::string exportOutput;     // output .crate file path (optional)

  // import parameters
  std::string importFile;       // .crate or archive file to import
  std::string importOutput;     // output .crate file path (optional)
  bool        importForce = false; // --force: skip checksum/spec validation

  void validate();
};

Args parseArguments(int argc, char** argv, unsigned &processed);
