// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args_pure.h"
#include "args.h"
#include "util.h"
#include "err.h"

#include <cctype>
#include <cstring>
#include <fstream>

#define ERR(msg...) \
  ERR2("parse args", msg)

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
  if (strEq(arg, "top"))      return CmdTop;
  if (strEq(arg, "inter-dns")) return CmdInterDns;
  if (strEq(arg, "vpn"))      return CmdVpn;
  if (strEq(arg, "inspect"))  return CmdInspect;
  if (strEq(arg, "migrate"))  return CmdMigrate;
  if (strEq(arg, "backup"))   return CmdBackup;
  if (strEq(arg, "restore"))  return CmdRestore;
  if (strEq(arg, "replicate")) return CmdReplicate;
  if (strEq(arg, "template"))  return CmdTemplate;
  if (strEq(arg, "retune"))    return CmdRetune;
  if (strEq(arg, "throttle"))  return CmdThrottle;
  return CmdNone;
}

}

// ===================================================================
// Args::validate — moved from cli/args.cpp so it can be unit-tested
// against the real Args class. Throws Exception on validation failure.
// (The original CmdNone path called the static err() helper which
// printed usage() and exit(1); switching to ERR() preserves
// "stderr-and-exit-1" behaviour via cli/main.cpp's catch chain, at
// the cost of losing the usage hint for that one path.)
// ===================================================================

void Args::validate() {
  switch (cmd) {
  case CmdCreate:
    if (createSpec.empty() && createTemplate.empty())
      ERR("the 'create' command requires either a spec file (-s, --spec) or a template (-t, --template)")
    if (!createTemplate.empty() && createSpec.empty()) {
      auto tryUser = STR(Util::Fs::getUserHomeDir() << "/.config/crate/templates/" << createTemplate << ".yml");
      auto trySys = STR("/usr/local/share/crate/templates/" << createTemplate << ".yml");
      if (Util::Fs::fileExists(tryUser))
        createSpec = tryUser;
      else if (Util::Fs::fileExists(trySys))
        createSpec = trySys;
      else if (Util::Fs::fileExists(createTemplate))
        createSpec = createTemplate;
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
    break;
  case CmdInfo:
    if (infoTarget.empty())
      ERR("the 'info' command requires a container name or JID")
    break;
  case CmdClean:
    break;
  case CmdConsole:
    if (consoleTarget.empty())
      ERR("the 'console' command requires a container name or JID")
    break;
  case CmdGui:
    if (guiSubcmd.empty())
      ERR("the 'gui' command requires a subcommand (list, focus, attach, url, tile, screenshot, resize)")
    if ((guiSubcmd == "focus" || guiSubcmd == "attach" || guiSubcmd == "url" ||
         guiSubcmd == "screenshot" || guiSubcmd == "resize") && guiTarget.empty())
      ERR("the 'gui " << guiSubcmd << "' command requires a target")
    if (guiSubcmd == "resize" && guiResolution.empty())
      ERR("the 'gui resize' command requires a resolution (e.g. 1920x1080)")
    break;
  case CmdStack:
    if (stackSubcmd.empty())
      ERR("the 'stack' command requires a subcommand (up, down, status, exec)")
    if (stackFile.empty())
      ERR("the 'stack' command requires a stack file")
    if (stackSubcmd == "exec" && stackExecContainer.empty())
      ERR("the 'stack exec' command requires a container name")
    if (stackSubcmd == "exec" && stackExecArgs.empty())
      ERR("the 'stack exec' command requires a command to execute")
    break;
  case CmdStats:
    if (statsTarget.empty())
      ERR("the 'stats' command requires a container name or JID")
    break;
  case CmdLogs:
    if (logsTarget.empty())
      ERR("the 'logs' command requires a container name or JID")
    break;
  case CmdStop:
    if (stopTarget.empty())
      ERR("the 'stop' command requires a container name or JID")
    break;
  case CmdRestart:
    if (restartTarget.empty())
      ERR("the 'restart' command requires a container name or JID")
    break;
  case CmdTop:
    // No arguments — `crate top` polls all running jails.
    break;
  case CmdInterDns:
    // No arguments — rebuilds /etc/hosts + unbound from JailQuery.
    break;
  case CmdVpn:
    if (vpnSubcmd.empty())
      ERR("the 'vpn' command requires a subcommand: 'wireguard' or 'ipsec'")
    if (vpnSubcmd != "wireguard" && vpnSubcmd != "ipsec")
      ERR("'vpn " << vpnSubcmd << "' is not supported (only 'wireguard' or 'ipsec')")
    if (vpnAction.empty())
      ERR("the 'vpn " << vpnSubcmd << "' command requires an action: 'render-conf'")
    if (vpnAction != "render-conf")
      ERR("'vpn " << vpnSubcmd << " " << vpnAction << "' is not supported (only 'render-conf')")
    if (vpnSpecFile.empty())
      ERR("the 'vpn " << vpnSubcmd << " render-conf' command requires a spec YAML file")
    break;
  case CmdInspect:
    if (inspectTarget.empty())
      ERR("the 'inspect' command requires a container name or JID")
    break;
  case CmdMigrate:
    if (migrateTarget.empty())
      ERR("the 'migrate' command requires a container name (positional arg)")
    if (migrateFrom.empty())
      ERR("the 'migrate' command requires --from <host:port>")
    if (migrateTo.empty())
      ERR("the 'migrate' command requires --to <host:port>")
    if (migrateFromTokenFile.empty())
      ERR("the 'migrate' command requires --from-token-file <path>")
    if (migrateToTokenFile.empty())
      ERR("the 'migrate' command requires --to-token-file <path>")
    break;
  case CmdBackup:
    if (backupTarget.empty())
      ERR("the 'backup' command requires a jail name (positional arg)")
    if (backupOutputDir.empty())
      ERR("the 'backup' command requires --output-dir <path>")
    break;
  case CmdRestore:
    if (restoreFile.empty())
      ERR("the 'restore' command requires a stream file (positional arg)")
    if (restoreDataset.empty())
      ERR("the 'restore' command requires --to <pool/jails/name>")
    break;
  case CmdReplicate:
    if (replicateTarget.empty())
      ERR("the 'replicate' command requires a jail name (positional arg)")
    if (replicateTo.empty())
      ERR("the 'replicate' command requires --to <[user@]host>")
    if (replicateDestDataset.empty())
      ERR("the 'replicate' command requires --dest-dataset <pool/jails/name>")
    break;
  case CmdTemplate:
    if (templateSubcmd.empty())
      ERR("the 'template' command requires a subcommand: 'warm'")
    if (templateSubcmd != "warm")
      ERR("'template " << templateSubcmd << "' is not supported (only 'warm')")
    if (warmTarget.empty())
      ERR("the 'template warm' command requires a jail name")
    if (warmOutputDataset.empty())
      ERR("the 'template warm' command requires --output <dataset>")
    break;
  case CmdRetune:
    if (retuneTarget.empty())
      ERR("the 'retune' command requires a jail name (positional arg)")
    if (retunePairs.empty() && retuneClear.empty() && !retuneShow)
      ERR("the 'retune' command needs at least one of --rctl, --clear, or --show")
    break;
  case CmdThrottle:
    if (throttleTarget.empty())
      ERR("the 'throttle' command requires a jail name (positional arg)")
    if (throttleIngressRate.empty() && throttleEgressRate.empty()
        && !throttleClear && !throttleShow)
      ERR("the 'throttle' command needs at least one of --ingress, --egress, --clear, or --show")
    break;
  default:
    ERR("no command was given")
  }
}
