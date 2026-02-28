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
  std::cout << "  run                        runs the containerized application (run 'crate run -h' for details)" << std::endl;
  std::cout << "  list                       list running crate containers (run 'crate list -h' for details)" << std::endl;
  std::cout << "  info                       show detailed container info (run 'crate info -h' for details)" << std::endl;
  std::cout << "  console                    open a shell in a running container (run 'crate console -h' for details)" << std::endl;
  std::cout << "  clean                      clean up orphaned resources (run 'crate clean -h' for details)" << std::endl;
  std::cout << "  validate                   validate a crate spec file (run 'crate validate -h' for details)" << std::endl;
  std::cout << "  snapshot                   manage ZFS snapshots (run 'crate snapshot -h' for details)" << std::endl;
  std::cout << "  export                     export a running container to a .crate archive" << std::endl;
  std::cout << "  import                     import and validate a .crate archive" << std::endl;
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

static void usageExport() {
  std::cout << "usage: crate export [-h|--help] [-o <output-file>] <name|JID>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Export a running container's filesystem to a .crate archive." << std::endl;
  std::cout << "The container must be running (created via 'crate run')." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -o, --output <file>        output .crate file (default: <hostname>-<date>.crate)" << std::endl;
  std::cout << "  -h, --help                 show this help screen" << std::endl;
  std::cout << "" << std::endl;
}

static void usageImport() {
  std::cout << "usage: crate import [-h|--help] [-o <output-file>] [-f|--force] <archive>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Import and validate a .crate archive." << std::endl;
  std::cout << "Verifies checksum, archive integrity, and +CRATE.SPEC presence." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -o, --output <file>        output .crate file (default: based on input name)" << std::endl;
  std::cout << "  -f, --force                skip checksum and spec validation" << std::endl;
  std::cout << "  -h, --help                 show this help screen" << std::endl;
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

static void usageList() {
  std::cout << "usage: crate list [-h|--help] [-j]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "List running crate containers with their JID, name, IP address, and path." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -j                                 output as JSON" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
}

static void usageInfo() {
  std::cout << "usage: crate info [-h|--help] <name|JID>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Show detailed information about a running crate container." << std::endl;
  std::cout << "The target can be a jail name, JID, or hostname." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
}

static void usageClean() {
  std::cout << "usage: crate clean [-h|--help] [-n|--dry-run]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Clean up orphaned resources from crashed or interrupted crate sessions." << std::endl;
  std::cout << "Removes stale jail directories, interface records, and context entries." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -n, --dry-run                      show what would be cleaned without making changes" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
}

static void usageConsole() {
  std::cout << "usage: crate console [-h|--help] [-u <user>|--user <user>] <name|JID> [command]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Open an interactive shell or run a command in a running crate container." << std::endl;
  std::cout << "The target can be a jail name, JID, or hostname." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -u, --user <user>                  login as the specified user (default: invoking user)" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  crate console myapp                open a shell in 'myapp'" << std::endl;
  std::cout << "  crate console 5                    open a shell in jail with JID 5" << std::endl;
  std::cout << "  crate console myapp /bin/sh        run /bin/sh in 'myapp'" << std::endl;
  std::cout << "  crate console -u root myapp        open a root shell in 'myapp'" << std::endl;
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
  if (strEq(arg, "list") || strEq(arg, "ls"))
    return CmdList;
  if (strEq(arg, "info"))
    return CmdInfo;
  if (strEq(arg, "clean"))
    return CmdClean;
  if (strEq(arg, "console"))
    return CmdConsole;
  if (strEq(arg, "export"))
    return CmdExport;
  if (strEq(arg, "import"))
    return CmdImport;

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
  case CmdList:
    // no required arguments
    break;
  case CmdInfo:
    if (infoTarget.empty())
      ERR("the 'info' command requires a container name or JID")
    break;
  case CmdClean:
    // no required arguments
    break;
  case CmdConsole:
    if (consoleTarget.empty())
      ERR("the 'console' command requires a container name or JID")
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
      case CmdExport:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageExport();
            exit(0);
          case 'o':
            args.exportOutput = getArgParam(++a, argc, argv);
            break;
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usageExport();
            exit(0);
          } else if (strEq(argLong, "output")) {
            args.exportOutput = getArgParam(++a, argc, argv);
            break;
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else if (args.exportTarget.empty()) {
          args.exportTarget = argv[a];
        } else {
          err("export takes exactly one container target");
        }
        break;
      case CmdImport:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageImport();
            exit(0);
          case 'o':
            args.importOutput = getArgParam(++a, argc, argv);
            break;
          case 'f':
            args.importForce = true;
            break;
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (strEq(argv[a], "--force")) {
          args.importForce = true;
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usageImport();
            exit(0);
          } else if (strEq(argLong, "output")) {
            args.importOutput = getArgParam(++a, argc, argv);
            break;
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else if (args.importFile.empty()) {
          args.importFile = argv[a];
        } else {
          err("import takes exactly one archive file");
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
      case CmdList:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageList();
            exit(0);
          case 'j':
            args.listJson = true;
            break;
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usageList();
            exit(0);
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else {
          err("unknown argument '%s'", argv[a]);
        }
        break;
      case CmdInfo:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageInfo();
            exit(0);
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usageInfo();
            exit(0);
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else if (!args.infoTarget.empty()) {
          err("info takes exactly one container target");
        } else {
          args.infoTarget = argv[a];
        }
        break;
      case CmdClean:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageClean();
            exit(0);
          case 'n':
            args.cleanDryRun = true;
            break;
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (strEq(argv[a], "--dry-run")) {
          args.cleanDryRun = true;
          break;
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usageClean();
            exit(0);
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else {
          err("unknown argument '%s'", argv[a]);
        }
        break;
      case CmdConsole:
        if (strEq(argv[a], "--")) {
          stop = true;
          break;
        } else if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageConsole();
            exit(0);
          case 'u':
            args.consoleUser = getArgParam(++a, argc, argv);
            break;
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (strEq(argv[a], "--user")) {
          args.consoleUser = getArgParam(++a, argc, argv);
          break;
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usageConsole();
            exit(0);
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else if (args.consoleTarget.empty()) {
          args.consoleTarget = argv[a];
        } else if (args.consoleCmd.empty()) {
          args.consoleCmd = argv[a];
        } else {
          // Append extra args to consoleCmd
          args.consoleCmd += " ";
          args.consoleCmd += argv[a];
        }
        break;
      }
    }
  }

  processed = a;
  return args;
}

