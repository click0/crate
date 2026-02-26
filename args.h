// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#pragma once

#include <string>

enum Command {CmdNone, CmdCreate, CmdRun, CmdValidate};

class Args {
public:
  Args() : logProgress (false) { }

  Command cmd;

  // general params
  bool logProgress; // log progress

  // create parameters
  std::string createSpec;
  std::string createOutput;

  // run parameters
  std::string runCrateFile;

  // validate parameters
  std::string validateSpec;

  void validate();
};

Args parseArguments(int argc, char** argv, unsigned &processed);
