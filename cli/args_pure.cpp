// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args_pure.h"

#include <cctype>
#include <cstring>

namespace ArgsPure {

bool strEq(const char *s1, const char *s2) {
  return strcmp(s1, s2) == 0;
}

char isShort(const char *arg) {
  if (arg[0] == '-' && (isalpha(arg[1]) || isdigit(arg[1])) && arg[2] == 0)
    return arg[1];
  return 0;
}

const char *isLong(const char *arg) {
  // Accept --foo where foo is [a-z0-9-]+
  if (arg[0] == '-' && arg[1] == '-') {
    for (int i = 2; arg[i]; i++)
      if (!islower(arg[i]) && !isdigit(arg[i]) && arg[i] != '-')
        return nullptr;
    return arg + 2;
  }
  return nullptr;
}

Command isCommand(const char *arg) {
  if (strEq(arg, "create"))   return CmdCreate;
  if (strEq(arg, "run"))      return CmdRun;
  if (strEq(arg, "validate")) return CmdValidate;
  if (strEq(arg, "snapshot")) return CmdSnapshot;
  if (strEq(arg, "list") || strEq(arg, "ls")) return CmdList;
  if (strEq(arg, "info"))     return CmdInfo;
  if (strEq(arg, "clean"))    return CmdClean;
  if (strEq(arg, "console"))  return CmdConsole;
  if (strEq(arg, "export"))   return CmdExport;
  if (strEq(arg, "import"))   return CmdImport;
  if (strEq(arg, "gui"))      return CmdGui;
  if (strEq(arg, "stack"))    return CmdStack;
  if (strEq(arg, "stats"))    return CmdStats;
  if (strEq(arg, "logs"))     return CmdLogs;
  if (strEq(arg, "stop"))     return CmdStop;
  if (strEq(arg, "restart"))  return CmdRestart;
  return CmdNone;
}

}
