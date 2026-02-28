// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include "args.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <iostream>
#include <fstream>


#define ERR(msg...) \
  ERR2("parse args", msg)

//
// internals
//

static bool strEq(const char *s1, const char *s2) {
  return strcmp(s1, s2) == 0;
}

static void usage() {
  std::cout << "usage: crate [-h|--help] [--no-color] [--version] COMMAND [...command arguments...]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -h, --help                 show this help screen" << std::endl;
  std::cout << "  -V, --version              show version information" << std::endl;
  std::cout << "      --no-color             disable colored output (also honors NO_COLOR env)" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Commands:" << std::endl;
  std::cout << "  create                     creates a container (run 'crate create -h' for details)" << std::endl;
  std::cout << "  run                        runs the containerzed application (run 'crate run -h' for details)" << std::endl;
  std::cout << "  validate                   validate a crate spec file (run 'crate validate -h' for details)" << std::endl;
  std::cout << "  snapshot                   manage ZFS snapshots (run 'crate snapshot -h' for details)" << std::endl;
  std::cout << "" << std::endl;
}

static void usageCreate() {
  std::cout << "usage: crate create [-s <spec-file>|--spec <spec-file>] [-o <output-create-file>|--output <output-create-file>]" << std::endl;
  std::cout << "       crate create --template <name> [-s <spec-file>] [-o <output-create-file>]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -s, --spec <spec-file>             crate specification (required unless --template)" << std::endl;
  std::cout << "  -t, --template <name>              use a template as base spec" << std::endl;
  std::cout << "  -o, --output <output-create-file>  output crate file" << std::endl;
  std::cout << "      --use-pkgbase                  bootstrap jail via pkgbase instead of base.txz" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Templates are searched in:" << std::endl;
  std::cout << "  ~/.config/crate/templates/<name>.yml" << std::endl;
  std::cout << "  /usr/local/share/crate/templates/<name>.yml" << std::endl;
  std::cout << "" << std::endl;
}

static void usageRun() {
  std::cout << "usage: crate run [-h|--help] <create-file>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
}

static void usageSnapshot() {
  std::cout << "usage: crate snapshot <subcommand> <dataset> [name] [name2]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Manage ZFS snapshots for container datasets." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Subcommands:" << std::endl;
  std::cout << "  create <dataset> [name]        create a snapshot (auto-names if omitted)" << std::endl;
  std::cout << "  list <dataset>                 list snapshots of a dataset" << std::endl;
  std::cout << "  restore <dataset> <name>       rollback to a snapshot" << std::endl;
  std::cout << "  delete <dataset> <name>        delete a snapshot" << std::endl;
  std::cout << "  diff <dataset> <s1> [s2]       show changes between snapshots" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -h, --help                     show this help screen" << std::endl;
  std::cout << "" << std::endl;
}

static void usageValidate() {
  std::cout << "usage: crate validate [-h|--help] <spec-file>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Validates a +CRATE.SPEC YAML file for syntax, schema and logical consistency." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
}

static void err(const char *msg) {
  fprintf(stderr, "failed to parse arguments: %s\n", msg);
  std::cout << "" << std::endl;
  usage();
  exit(1);
}

static void err(const char *fmt, const char *arg) {
  fprintf(stderr, "failed to parse arguments: ");
  fprintf(stderr, fmt, arg);
  fprintf(stderr, "\n");
  std::cout << "" << std::endl;
  usage();
  exit(1);
}

static const char isShort(const char* arg) {
  if (arg[0] == '-' && (isalpha(arg[1]) || isdigit(arg[1])) && arg[2] == 0)
    return arg[1];
  return 0;
}

static const char* isLong(const char* arg) {
  if (arg[0] == '-' && arg[1] == '-') {
    for (int i = 2; arg[i]; i++)
      if (!islower(arg[i]) || !isdigit(arg[i]))
        return nullptr;
    return arg + 2;
  }

  return nullptr;
}

static Command isCommand(const char* arg) {
  if (strEq(arg, "create"))
    return CmdCreate;
  if (strEq(arg, "run"))
    return CmdRun;
  if (strEq(arg, "validate"))
    return CmdValidate;
  if (strEq(arg, "snapshot"))
    return CmdSnapshot;

  return CmdNone;
}

static const char* getArgParam(int aidx, int argc, char** argv) {
  if (aidx >= argc)
    err("argument parameter expected but no more arguments were supplied");
  if (argv[aidx][0] == '-')
    err("argument parameter can't begin from the hyphen");
  return argv[aidx];
}

//
// interface
//

void Args::validate() {
  switch (cmd) {
  case CmdCreate:
    if (createSpec.empty() && createTemplate.empty())
      ERR("the 'create' command requires either a spec file (-s, --spec) or a template (-t, --template)")
    if (!createTemplate.empty() && createSpec.empty()) {
      // resolve template path: check user dir, then system dir
      auto tryUser = STR(Util::Fs::getUserHomeDir() << "/.config/crate/templates/" << createTemplate << ".yml");
      auto trySys = STR("/usr/local/share/crate/templates/" << createTemplate << ".yml");
      if (Util::Fs::fileExists(tryUser))
        createSpec = tryUser;
      else if (Util::Fs::fileExists(trySys))
        createSpec = trySys;
      else if (Util::Fs::fileExists(createTemplate))
        createSpec = createTemplate; // treat as path
      else
        ERR("template '" << createTemplate << "' not found (searched " << tryUser << " and " << trySys << ")")
    }
    break;
  case CmdRun:
    if (runCrateFile.empty())
      ERR("the 'run' command requires the crate file as an argument (-f, --file)")
    if (!std::ifstream(runCrateFile).good())
      ERR("the file passed to the 'run' command can't be opened: " << runCrateFile)
    break;
  case CmdValidate:
    if (validateSpec.empty())
      ERR("the 'validate' command requires a spec file argument")
    break;
  case CmdSnapshot:
    if (snapshotSubcmd.empty())
      ERR("the 'snapshot' command requires a subcommand (create, list, restore, delete, diff)")
    if (snapshotDataset.empty())
      ERR("the 'snapshot' command requires a ZFS dataset name")
    if ((snapshotSubcmd == "restore" || snapshotSubcmd == "delete") && snapshotName.empty())
      ERR("the 'snapshot " << snapshotSubcmd << "' command requires a snapshot name")
    if (snapshotSubcmd == "diff" && snapshotName.empty())
      ERR("the 'snapshot diff' command requires at least one snapshot name")
    break;
  default:
    err("no command was given");
  }
}

Args parseArguments(int argc, char** argv, unsigned &processed) {
  Args args;

  // first, see if the command form is a shortened one: 'crate {name}.yml' or 'crate {name}.crate ...'
  if (argc >= 2 && argv[1][0] != '-') {
    if (argc == 2 && Util::Fs::hasExtension(argv[1], ".yml")) {
      args.cmd = CmdCreate;
      args.createSpec = argv[1];
      processed = 2;
      return args;
    } else if (Util::Fs::hasExtension(argv[1], ".crate") && Util::Fs::isXzArchive(argv[1])) {
      args.cmd = CmdRun;
      args.runCrateFile = argv[1];
      processed = 2;
      return args;
    }
  }

  enum Loc {LocBeforeCmd, LocAfterCmd};
  Loc loc = LocBeforeCmd;
  int a;
  bool stop = false;
  for (a = 1; !stop && a < argc; a++) {
    switch (loc) {
    case LocBeforeCmd:
      if (strEq(argv[a], "--no-color")) {
        args.noColor = true;
        break;
      } else if (strEq(argv[a], "--version")) {
        std::cout << "crate 0.2.1" << std::endl;
        exit(0);
      } else if (auto argShort = isShort(argv[a])) {
        switch (argShort) {
        case 'h':
          usage();
          exit(0);
        case 'p':
          args.logProgress = true;
          break;
        case 'V':
          std::cout << "crate 0.2.1" << std::endl;
          exit(0);
        default:
          err("unsupported short option '%s'", argv[a]);
        }
      } else if (auto argLong = isLong(argv[a])) {
        if (strEq(argLong, "help")) {
          usage();
          exit(0);
        } else if (strEq(argLong, "log-progress")) {
          args.logProgress = true;
          break;
        } else {
          err("unsupported long option '%s'", argv[a]);
        }
      } else if (auto cmd = isCommand(argv[a])) {
        args.cmd = cmd;
        loc = LocAfterCmd;
        break;
      } else {
        err("unknown argument '%s'", argv[a]);
      }

    case LocAfterCmd:
      switch (args.cmd) {
      case CmdNone:
        // impossible
        break;
      case CmdCreate:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageCreate();
            exit(0);
          case 's':
            args.createSpec = getArgParam(++a, argc, argv);
            break;
          case 't':
            args.createTemplate = getArgParam(++a, argc, argv);
            break;
          case 'o':
            args.createOutput = getArgParam(++a, argc, argv);
            break;
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (strEq(argv[a], "--use-pkgbase")) {
          args.usePkgbase = true;
          break;
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usageCreate();
            exit(0);
          } else if (strEq(argLong, "spec")) {
            args.createSpec = getArgParam(++a, argc, argv);
            break;
          } else if (strEq(argLong, "template")) {
            args.createTemplate = getArgParam(++a, argc, argv);
            break;
          } else if (strEq(argLong, "output")) {
            args.createOutput = getArgParam(++a, argc, argv);
            break;
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else {
          err("unknown argument '%s'", argv[a]);
        }
        break;
      case CmdRun:
        if (strEq(argv[a], "--")) {
          stop = true;
          break;
        } else if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageRun();
            exit(0);
          case 'f':
            args.runCrateFile = getArgParam(++a, argc, argv);
            break;
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usage();
            exit(0);
          } else if (strEq(argLong, "file")) {
            args.runCrateFile = getArgParam(++a, argc, argv);
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else {
          err("unknown argument '%s'", argv[a]);
        }
        break;
      case CmdValidate:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageValidate();
            exit(0);
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usageValidate();
            exit(0);
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else if (!args.validateSpec.empty()) {
          err("validate takes exactly one spec file argument");
        } else {
          args.validateSpec = argv[a];
        }
        break;
      case CmdSnapshot:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageSnapshot();
            exit(0);
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usageSnapshot();
            exit(0);
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else if (args.snapshotSubcmd.empty()) {
          args.snapshotSubcmd = argv[a];
          if (args.snapshotSubcmd != "create" && args.snapshotSubcmd != "list" &&
              args.snapshotSubcmd != "restore" && args.snapshotSubcmd != "delete" &&
              args.snapshotSubcmd != "diff")
            err("unknown snapshot subcommand '%s'", argv[a]);
        } else if (args.snapshotDataset.empty()) {
          args.snapshotDataset = argv[a];
        } else if (args.snapshotName.empty()) {
          args.snapshotName = argv[a];
        } else if (args.snapshotName2.empty()) {
          args.snapshotName2 = argv[a];
        } else {
          err("too many arguments for 'snapshot' command");
        }
        break;
      }
    }
  }

  processed = a;
  return args;
}

