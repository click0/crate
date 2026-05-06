// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "args_pure.h"
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

// Forward to pure helpers (definitions in cli/args_pure.cpp)
static inline bool        strEq(const char *s1, const char *s2) { return ArgsPure::strEq(s1, s2); }
static inline char        isShort(const char *arg)              { return ArgsPure::isShort(arg); }
static inline const char *isLong(const char *arg)               { return ArgsPure::isLong(arg); }
static inline Command     isCommand(const char *arg)            { return ArgsPure::isCommand(arg); }

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
  std::cout << "  gui                        manage GUI sessions (run 'crate gui -h' for details)" << std::endl;
  std::cout << "  stack                      manage multi-container stacks (run 'crate stack -h' for details)" << std::endl;
  std::cout << "  stats                      show container resource usage (run 'crate stats -h' for details)" << std::endl;
  std::cout << "  logs                       view container logs (run 'crate logs -h' for details)" << std::endl;
  std::cout << "  stop                       stop a running container (run 'crate stop -h' for details)" << std::endl;
  std::cout << "  restart                    restart a running container (run 'crate restart -h' for details)" << std::endl;
  std::cout << "  top                        live resource monitor across all running containers" << std::endl;
  std::cout << "  inter-dns                  rebuild the global .crate DNS zone from running jails" << std::endl;
  std::cout << "  vpn                        VPN tooling — currently 'vpn wireguard render-conf <spec.yml>'" << std::endl;
  std::cout << "  inspect TARGET             print full JSON snapshot of a running container's state" << std::endl;
  std::cout << "  migrate TARGET --from EP --to EP  move a container between hosts via the F2 API" << std::endl;
  std::cout << "  backup TARGET --output-dir DIR  take a ZFS-send stream of the jail (incremental supported)" << std::endl;
  std::cout << "  backup-prune DIR --keep SPEC   delete old .zstream files by retention bucket (Proxmox-style)" << std::endl;
  std::cout << "  restore STREAM --to DATASET     replay a backup stream into a fresh dataset" << std::endl;
  std::cout << "  replicate TARGET --to HOST --dest-dataset DS  stream a ZFS snapshot to a remote host" << std::endl;
  std::cout << "  template warm TARGET --output DS  capture jail's on-disk state as a ZFS warm template" << std::endl;
  std::cout << "  retune TARGET --rctl K=V...   live-tune jail RCTL limits without restart (--show, --clear)" << std::endl;
  std::cout << "  throttle TARGET --ingress R --egress R    dummynet token-bucket network shaping" << std::endl;
  std::cout << "  doctor [-j]                health check for crate host (kernel modules, commands, ZFS, jails, ...)" << std::endl;
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
  std::cout << "      --var KEY=VALUE                substitute ${KEY} with VALUE in spec YAML (repeatable)" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Templates are searched in:" << std::endl;
  std::cout << "  ~/.config/crate/templates/<name>.yml" << std::endl;
  std::cout << "  /usr/local/share/crate/templates/<name>.yml" << std::endl;
  std::cout << "" << std::endl;
}

static void usageRun() {
  std::cout << "usage: crate run [-h|--help] [--var KEY=VALUE ...] -f <create-file>" << std::endl;
  std::cout << "       crate run [--var KEY=VALUE ...] --warm-base <dataset> --name <name>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Two modes:" << std::endl;
  std::cout << "  -f / --file <archive>             cold-create from .crate (extract base.txz, run pkg, ...)" << std::endl;
  std::cout << "  --warm-base <dataset>             skip cold-create: clone the warm-template ZFS dataset" << std::endl;
  std::cout << "                                    produced by `crate template warm` and boot from it." << std::endl;
  std::cout << "                                    Spec comes from +CRATE.SPEC inside the cloned dataset." << std::endl;
  std::cout << "  --name <name>                     jail name; required and only valid with --warm-base" << std::endl;
  std::cout << "                                    (without --warm-base the name is derived from the .crate)" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Common options:" << std::endl;
  std::cout << "      --var KEY=VALUE                substitute ${KEY} with VALUE in embedded spec (repeatable)" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  crate run -f firefox.crate" << std::endl;
  std::cout << "  crate run --warm-base tank/templates/firefox-warm --name firefox" << std::endl;
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
  std::cout << "usage: crate export [-h|--help] [-o <file>] [-P <pass>] [-K <key>] <name|JID>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Export a running container's filesystem to a .crate archive." << std::endl;
  std::cout << "The container must be running (created via 'crate run')." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -o, --output <file>           output .crate file (default: <hostname>-<date>.crate)" << std::endl;
  std::cout << "  -P, --passphrase-file <file>  encrypt with passphrase from file (mode 0600);" << std::endl;
  std::cout << "                                AES-256-CBC + PBKDF2; integrity via .sha256 sidecar" << std::endl;
  std::cout << "  -K, --sign-key <file>         sign with ed25519 secret key (PEM, mode 0600);" << std::endl;
  std::cout << "                                produces <archive>.sig sidecar" << std::endl;
  std::cout << "  -h, --help                    show this help screen" << std::endl;
  std::cout << "" << std::endl;
}

static void usageImport() {
  std::cout << "usage: crate import [-h|--help] [-o <file>] [-f] [-P <pass>] [-V <key>] <archive>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Import and validate a .crate archive." << std::endl;
  std::cout << "Verifies checksum, archive integrity, and +CRATE.SPEC presence." << std::endl;
  std::cout << "Encrypted archives are auto-detected; -P is required for those." << std::endl;
  std::cout << "If a <archive>.sig sidecar exists, -V <public-key> is required (use -f to skip)." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -o, --output <file>           output .crate file (default: based on input name)" << std::endl;
  std::cout << "  -f, --force                   skip checksum / signature / spec validation" << std::endl;
  std::cout << "  -P, --passphrase-file <file>  decrypt with passphrase from file (mode 0600)" << std::endl;
  std::cout << "  -V, --verify-key <file>       verify ed25519 .sig sidecar with this public key (PEM)" << std::endl;
  std::cout << "  -h, --help                    show this help screen" << std::endl;
  std::cout << "" << std::endl;
}

static void usageValidate() {
  std::cout << "usage: crate validate [--strict] <spec-file>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Validates a +CRATE.SPEC YAML file for syntax, schema and logical consistency." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "      --strict      promote warnings AND extra structural checks to errors:" << std::endl;
  std::cout << "                       - duplicate inbound TCP/UDP host ports" << std::endl;
  std::cout << "                       - duplicate share destinations" << std::endl;
  std::cout << "                       - empty mount source/destination" << std::endl;
  std::cout << "                       - x11/mode=shared (no display isolation)" << std::endl;
  std::cout << "                       - missing memoryuse/maxproc RCTL caps" << std::endl;
  std::cout << "                     Exits non-zero on first error class found." << std::endl;
  std::cout << "  -h, --help        show this help screen" << std::endl;
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

static void usageGui() {
  std::cout << "usage: crate gui <subcommand> [options] [target]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Manage GUI sessions for running crate containers." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Subcommands:" << std::endl;
  std::cout << "  list [-j]                  list active GUI sessions" << std::endl;
  std::cout << "  focus <target>             raise container's X window (desktop mode)" << std::endl;
  std::cout << "  attach <target>            open VNC viewer to headless container" << std::endl;
  std::cout << "  url <target>               print noVNC URL for headless container" << std::endl;
  std::cout << "  tile                       tile all Xephyr windows on screen" << std::endl;
  std::cout << "  screenshot <target> [-o f] capture screenshot of container display" << std::endl;
  std::cout << "  resize <target> <WxH>      resize container display" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -j                         output as JSON (for list)" << std::endl;
  std::cout << "  -o, --output <file>        output file (for screenshot)" << std::endl;
  std::cout << "  -h, --help                 show this help screen" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Target can be a jail name, JID, or display number." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  crate gui list             list all GUI sessions" << std::endl;
  std::cout << "  crate gui focus firefox    raise firefox container window" << std::endl;
  std::cout << "  crate gui attach myapp     connect VNC viewer to myapp" << std::endl;
  std::cout << "  crate gui url myapp        print noVNC URL for myapp" << std::endl;
  std::cout << "  crate gui screenshot firefox -o shot.png" << std::endl;
  std::cout << "" << std::endl;
}

static void usageStack() {
  std::cout << "usage: crate stack <subcommand> [options] <stack-file>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Manage multi-container stacks defined in a single YAML file." << std::endl;
  std::cout << "Containers are started in dependency order and stopped in reverse." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Subcommands:" << std::endl;
  std::cout << "  up <stack-file>            create and start all containers in the stack" << std::endl;
  std::cout << "  down <stack-file>          stop and remove all containers in the stack" << std::endl;
  std::cout << "  status <stack-file>        show status of all containers in the stack" << std::endl;
  std::cout << "  exec <stack-file> <name> -- <cmd>  run command in a stack container" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Stack file format:" << std::endl;
  std::cout << "  containers:" << std::endl;
  std::cout << "    postgres:" << std::endl;
  std::cout << "      crate: postgres.crate" << std::endl;
  std::cout << "    app:" << std::endl;
  std::cout << "      crate: myapp.crate" << std::endl;
  std::cout << "      depends: [postgres]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "      --var KEY=VALUE        substitute ${KEY} with VALUE in spec (repeatable)" << std::endl;
  std::cout << "  -h, --help                 show this help screen" << std::endl;
  std::cout << "" << std::endl;
}

static void usageStats() {
  std::cout << "usage: crate stats [-h|--help] [-j|--json] <name|JID>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Show resource usage statistics for a running container." << std::endl;
  std::cout << "Displays CPU%, memory, PIDs, I/O, and network I/O." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -j, --json                         output as JSON" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  crate stats myapp                  show stats for 'myapp'" << std::endl;
  std::cout << "  crate stats 5                      show stats for jail with JID 5" << std::endl;
  std::cout << "  crate stats myapp --json           output stats as JSON" << std::endl;
  std::cout << "" << std::endl;
}

static void usageLogs() {
  std::cout << "usage: crate logs [-h|--help] [-f|--follow] [--tail N] <name|JID>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "View log output from a container." << std::endl;
  std::cout << "Checks /var/log/crate/<name>/ and falls back to jail /var/log/messages." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -f, --follow                       stream new log output (like tail -f)" << std::endl;
  std::cout << "      --tail N                       show last N lines (default: all)" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  crate logs myapp                   show all logs for 'myapp'" << std::endl;
  std::cout << "  crate logs myapp --tail 50         show last 50 lines" << std::endl;
  std::cout << "  crate logs myapp -f                follow log output" << std::endl;
  std::cout << "" << std::endl;
}

static void usageStop() {
  std::cout << "usage: crate stop [-h|--help] [-t TIMEOUT] <name|JID>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Stop a running container." << std::endl;
  std::cout << "Sends SIGTERM to all processes, waits for graceful shutdown," << std::endl;
  std::cout << "then sends SIGKILL if the timeout expires." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -t TIMEOUT                         seconds to wait before SIGKILL (default: 10)" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  crate stop myapp                   stop 'myapp' (10s timeout)" << std::endl;
  std::cout << "  crate stop -t 30 myapp             stop with 30s grace period" << std::endl;
  std::cout << "" << std::endl;
}

static void usageRestart() {
  std::cout << "usage: crate restart [-h|--help] [-t TIMEOUT] <name|JID>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Restart a running container." << std::endl;
  std::cout << "Stops the container and then starts it again from its .crate file." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -t TIMEOUT                         seconds to wait before SIGKILL during stop (default: 10)" << std::endl;
  std::cout << "  -h, --help                         show this help screen" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  crate restart myapp                restart 'myapp'" << std::endl;
  std::cout << "  crate restart -t 30 myapp          restart with 30s stop timeout" << std::endl;
  std::cout << "" << std::endl;
}

static void usageTop() {
  std::cout << "usage: crate top [-h|--help]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Live, htop-style resource monitor for crate-managed jails." << std::endl;
  std::cout << "Refreshes once per second; press 'q' or Ctrl-C to quit." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "If stdout is not a terminal, prints a single frame and exits" << std::endl;
  std::cout << "(useful for piping into watch(1), grep, etc.)." << std::endl;
  std::cout << "" << std::endl;
}

static void usageInterDns() {
  std::cout << "usage: crate inter-dns [-h|--help]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Rebuild the global .crate DNS zone from currently running jails." << std::endl;
  std::cout << "Updates /etc/hosts (between crate-marker comments) and writes" << std::endl;
  std::cout << "/usr/local/etc/unbound/conf.d/crate.conf, then asks unbound to" << std::endl;
  std::cout << "reload. Run after every container start/stop, or wire it into" << std::endl;
  std::cout << "lifecycle hooks." << std::endl;
  std::cout << "" << std::endl;
}

static void usageBackup() {
  std::cout << "usage: crate backup <jail> --output-dir <dir>" << std::endl;
  std::cout << "                    [--since <snapshot>] [--auto-incremental]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Take a fresh ZFS snapshot of the jail's dataset and write a" << std::endl;
  std::cout << "`zfs send` stream to <dir>/<jail>-<timestamp>.zstream." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Stream type:" << std::endl;
  std::cout << "  default              full stream" << std::endl;
  std::cout << "  --since <snap>       incremental from <snap> (zfs send -i)" << std::endl;
  std::cout << "  --auto-incremental   incremental from the most recent backup-*" << std::endl;
  std::cout << "                       snapshot on the dataset; falls back to full" << std::endl;
  std::cout << "                       on first run." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Filenames sort lexicographically by time so retention pruning" << std::endl;
  std::cout << "is trivial — `ls -1 | tail -n +N` keeps the latest N." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Restore with: crate restore <stream> --to <pool/jails/name>" << std::endl;
  std::cout << "" << std::endl;
}

static void usageBackupPrune() {
  std::cout << "usage: crate backup-prune <dir> --keep <spec>" << std::endl;
  std::cout << "                          [--jail NAME] [--dry-run] [--delete-orphans]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Apply a Proxmox-style retention policy to .zstream files left by" << std::endl;
  std::cout << "`crate backup`. Newest stream per bucket survives; the rest are" << std::endl;
  std::cout << "deleted. Bucket types: hourly | daily | weekly | monthly." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Retention spec (same syntax as parseRetention):" << std::endl;
  std::cout << "  hourly=N,daily=N,weekly=N,monthly=N    any subset; combine freely" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  crate backup-prune /backups --keep daily=7,weekly=4,monthly=6" << std::endl;
  std::cout << "  crate backup-prune /backups --keep daily=14 --jail postgres" << std::endl;
  std::cout << "  crate backup-prune /backups --keep daily=7 --dry-run" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Incrementals (.inc-from-*.zstream) inherit their base full's fate:" << std::endl;
  std::cout << "  base kept     -> incremental kept (chain stays restorable)" << std::endl;
  std::cout << "  base removed  -> incremental flagged 'orphan' (kept by default)" << std::endl;
  std::cout << "                   --delete-orphans removes them too." << std::endl;
  std::cout << "" << std::endl;
}

static void usageDoctor() {
  std::cout << "usage: crate doctor [-j|--json] [-h|--help]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Run a one-shot health check on the crate host: kernel modules," << std::endl;
  std::cout << "external commands, filesystem dirs + free space, ZFS pools," << std::endl;
  std::cout << "crated.conf parseability, running jails, audit-log size." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Output format:" << std::endl;
  std::cout << "  default                   human-readable categorized table" << std::endl;
  std::cout << "  -j, --json                 machine-readable {checks: [...], summary}" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Exit codes:" << std::endl;
  std::cout << "  0   all checks PASS" << std::endl;
  std::cout << "  1   at least one WARN, no FAIL  (degraded but functional)" << std::endl;
  std::cout << "  2   at least one FAIL          (operator action needed)" << std::endl;
  std::cout << "" << std::endl;
}

static void usageThrottle() {
  std::cout << "usage: crate throttle <jail> [--ingress RATE] [--egress RATE]" << std::endl;
  std::cout << "                       [--ingress-burst BYTES] [--egress-burst BYTES]" << std::endl;
  std::cout << "                       [--queue N] [--clear] [--show]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "True token-bucket network rate limiting via dummynet(4) — sustained" << std::endl;
  std::cout << "rate (bw) plus burst capacity. Sister to `crate retune` (which targets" << std::endl;
  std::cout << "RCTL hard caps for CPU/disk/memory)." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Rate format (bit/s OR byte/s — bare 'NM' is REJECTED to avoid ambiguity):" << std::endl;
  std::cout << "  10Mbit/s  100Kbit/s  1Gbit/s     bit/s units" << std::endl;
  std::cout << "  10MB/s    100KB/s    1GB/s       byte/s (uppercase B mandatory)" << std::endl;
  std::cout << "  10000                            plain integer = bytes/s" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Burst (bytes only — no /s):  1MB | 100KB | 100000" << std::endl;
  std::cout << "Queue: slot count 1..1000  OR  byte size 100KB | 1MB" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  crate throttle torrent --ingress 10Mbit/s --egress 5Mbit/s --burst 1MB" << std::endl;
  std::cout << "  crate throttle torrent --egress 1Mbit/s --queue 100" << std::endl;
  std::cout << "  crate throttle torrent --show" << std::endl;
  std::cout << "  crate throttle torrent --clear" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Pipe IDs are deterministic per JID (10000 + jid*2; +1 for egress)." << std::endl;
  std::cout << "Repeating the command replaces the previous config — no orphaned pipes." << std::endl;
  std::cout << "" << std::endl;
}

static void usageRetune() {
  std::cout << "usage: crate retune <jail> [--rctl KEY=VALUE]... [--clear KEY]... [--show]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Live RCTL adjustment for a running jail — no restart required." << std::endl;
  std::cout << "Throttle a runaway container (torrent client suddenly sucking the" << std::endl;
  std::cout << "disk) without losing its in-memory state." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Supported keys (whitelisted; typos give a helpful diagnostic):" << std::endl;
  std::cout << "  pcpu                       integer 0..100 (percent of one core)" << std::endl;
  std::cout << "  memoryuse, vmemoryuse      integer with K/M/G/T suffix (1024-based)" << std::endl;
  std::cout << "  readbps, writebps          byte rate, K/M/G/T suffix" << std::endl;
  std::cout << "  readiops, writeiops        operations per second (no suffix)" << std::endl;
  std::cout << "  maxproc, openfiles, nthr   plain integer counts" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  crate retune torrent --rctl writebps=2M --rctl readbps=2M" << std::endl;
  std::cout << "  crate retune torrent --rctl pcpu=20 --show" << std::endl;
  std::cout << "  crate retune ide      --clear pcpu --clear writebps" << std::endl;
  std::cout << "" << std::endl;
}

static void usageTemplate() {
  std::cout << "usage: crate template warm <jail> --output <dataset> [--promote]" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Capture the on-disk state of a running jail as a ZFS clone the" << std::endl;
  std::cout << "operator can later pass to `crate run --warm-base <dataset>`." << std::endl;
  std::cout << "Skips cold-create work like pkg install or profile init." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "What's captured:  pkg/var caches, fontconfig, db migrations," << std::endl;
  std::cout << "                  npm install output, anything written to disk." << std::endl;
  std::cout << "What's NOT:       process memory, open fds, browser tabs," << std::endl;
  std::cout << "                  X11 sessions. (See lib/warm_pure.h for why" << std::endl;
  std::cout << "                  Firecracker-style memory snapshot is" << std::endl;
  std::cout << "                  out-of-scope for jail-based architectures.)" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  --output DATASET   destination ZFS dataset (e.g. tank/templates/firefox-warm)" << std::endl;
  std::cout << "  --promote          run `zfs promote` on the clone so it's no" << std::endl;
  std::cout << "                     longer dependent on the source snapshot — useful" << std::endl;
  std::cout << "                     when the operator wants to delete old warm" << std::endl;
  std::cout << "                     snapshots without breaking the template." << std::endl;
  std::cout << "" << std::endl;
}

static void usageReplicate() {
  std::cout << "usage: crate replicate <jail> --to <[user@]host>" << std::endl;
  std::cout << "                       --dest-dataset <pool/jails/name>" << std::endl;
  std::cout << "                       [--since <snap> | --auto-incremental]" << std::endl;
  std::cout << "                       [--ssh-port N] [--ssh-key PATH]" << std::endl;
  std::cout << "                       [--ssh-config PATH]" << std::endl;
  std::cout << "                       [--ssh-opt KEY=VAL]..." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Stream a ZFS snapshot of <jail>'s dataset to a remote host:" << std::endl;
  std::cout << "  zfs send <ds>@<snap> | ssh <opts> <host> 'zfs recv <dest>'" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Stream type:" << std::endl;
  std::cout << "  default              full stream" << std::endl;
  std::cout << "  --since <snap>       incremental from <snap> (zfs send -i)" << std::endl;
  std::cout << "  --auto-incremental   incremental from the most recent backup-*" << std::endl;
  std::cout << "                       snapshot on the source dataset; falls back" << std::endl;
  std::cout << "                       to full on first run." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "SSH transport:" << std::endl;
  std::cout << "  --ssh-port N         non-default port (otherwise: ssh's default 22)" << std::endl;
  std::cout << "  --ssh-key PATH       absolute path to identity file (passed via -i)" << std::endl;
  std::cout << "  --ssh-config PATH    absolute path to ssh_config (passed via -F)" << std::endl;
  std::cout << "  --ssh-opt KEY=VAL    repeatable; passed verbatim as `-o KEY=VAL`." << std::endl;
  std::cout << "                       Examples: StrictHostKeyChecking=no," << std::endl;
  std::cout << "                                 UserKnownHostsFile=/dev/null," << std::endl;
  std::cout << "                                 ProxyJump=bastion," << std::endl;
  std::cout << "                                 ConnectTimeout=30." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "BatchMode=yes and ServerAliveInterval=30 are set as defaults." << std::endl;
  std::cout << "" << std::endl;
}

static void usageRestore() {
  std::cout << "usage: crate restore <stream-file> --to <pool/jails/name>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Replay a `crate backup` stream into a fresh ZFS dataset." << std::endl;
  std::cout << "Equivalent to: zfs recv <dest> < <stream-file>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "For incremental streams, the dataset must already contain the" << std::endl;
  std::cout << "parent snapshot — apply chained incrementals in order." << std::endl;
  std::cout << "" << std::endl;
}

static void usageMigrate() {
  std::cout << "usage: crate migrate <name> --from <ep> --to <ep>" << std::endl;
  std::cout << "                     --from-token-file <path> --to-token-file <path>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Move a container between two crated-managed hosts via the F2 API." << std::endl;
  std::cout << "Steps (executed in order; the source is stopped only after the" << std::endl;
  std::cout << "destination has started):" << std::endl;
  std::cout << "  1. POST {from}/api/v1/containers/<name>/export" << std::endl;
  std::cout << "  2. GET  {from}/api/v1/exports/<file>            (download to /tmp)" << std::endl;
  std::cout << "  3. POST {to}/api/v1/imports/<name>              (octet-stream upload)" << std::endl;
  std::cout << "  4. POST {to}/api/v1/containers/<name>/start" << std::endl;
  std::cout << "  5. POST {from}/api/v1/containers/<name>/stop" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Endpoint format: 'host:port' or 'https://host:port' or '[::1]:9800'." << std::endl;
  std::cout << "Tokens are read from files (chmod 600) — never passed on the command" << std::endl;
  std::cout << "line so they don't appear in 'ps' listings." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Requires curl(1)." << std::endl;
  std::cout << "" << std::endl;
}

static void usageInspect() {
  std::cout << "usage: crate inspect <name|JID>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Print a JSON snapshot of the running container's runtime state:" << std::endl;
  std::cout << "  - identity (name, JID, hostname, path, kernel release)" << std::endl;
  std::cout << "  - jail params (allow.*, securelevel, vnet, ...)" << std::endl;
  std::cout << "  - interfaces, mounts inside the jail rootfs" << std::endl;
  std::cout << "  - RCTL counters (cputime, memoryuse, ...)" << std::endl;
  std::cout << "  - ZFS dataset and origin (if cloned)" << std::endl;
  std::cout << "  - GUI session (display, VNC/WS ports, mode)" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Output is pretty-printed with 2-space indent and a stable key" << std::endl;
  std::cout << "order, so diffs across snapshots are clean." << std::endl;
  std::cout << "" << std::endl;
}

static void usageVpn() {
  std::cout << "usage: crate vpn <wireguard|ipsec> render-conf <spec.yml>" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Render a config file from a small YAML spec. Validates keys," << std::endl;
  std::cout << "CIDRs, hosts, and proposal strings before emitting the canonical" << std::endl;
  std::cout << "INI text on stdout." << std::endl;
  std::cout << "" << std::endl;
  std::cout << "WireGuard spec example (wg-quick(8) compatible output):" << std::endl;
  std::cout << "  interface:" << std::endl;
  std::cout << "    private_key: <base64>" << std::endl;
  std::cout << "    addresses: [10.0.0.1/24]" << std::endl;
  std::cout << "    listen_port: 51820" << std::endl;
  std::cout << "  peers:" << std::endl;
  std::cout << "    - public_key: <base64>" << std::endl;
  std::cout << "      allowed_ips: [10.0.0.2/32]" << std::endl;
  std::cout << "      endpoint: vpn.example.com:51820" << std::endl;
  std::cout << "      persistent_keepalive: 25" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "IPsec spec example (strongSwan ipsec.conf compatible output):" << std::endl;
  std::cout << "  conns:" << std::endl;
  std::cout << "    - name: dc1-dc2" << std::endl;
  std::cout << "      left: 203.0.113.5" << std::endl;
  std::cout << "      leftsubnet: [10.0.1.0/24]" << std::endl;
  std::cout << "      right: 198.51.100.7" << std::endl;
  std::cout << "      rightsubnet: [10.0.2.0/24]" << std::endl;
  std::cout << "      keyexchange: ikev2" << std::endl;
  std::cout << "      authby: psk" << std::endl;
  std::cout << "      auto: start" << std::endl;
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

// strEq, isShort, isLong, isCommand moved to cli/args_pure.cpp

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

// Args::validate moved to cli/args_pure.cpp so it can be unit-tested
// against the real Args class without dragging in the rest of args.cpp
// (which depends on rang/usage()/exit()).

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
        std::cout << "crate 0.8.9" << std::endl;
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
          std::cout << "crate 0.8.9" << std::endl;
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
        } else if (strEq(argv[a], "--var")) {
          const char *kv = getArgParam(++a, argc, argv);
          std::string kvs(kv);
          auto eq = kvs.find('=');
          if (eq == std::string::npos)
            err("--var requires KEY=VALUE format, got '%s'", kv);
          args.vars[kvs.substr(0, eq)] = kvs.substr(eq + 1);
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
        } else if (strEq(argv[a], "--var")) {
          const char *kv = getArgParam(++a, argc, argv);
          std::string kvs(kv);
          auto eq = kvs.find('=');
          if (eq == std::string::npos)
            err("--var requires KEY=VALUE format, got '%s'", kv);
          args.vars[kvs.substr(0, eq)] = kvs.substr(eq + 1);
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
          } else if (strEq(argLong, "warm-base")) {
            args.runWarmBase = getArgParam(++a, argc, argv);
          } else if (strEq(argLong, "name")) {
            args.runName = getArgParam(++a, argc, argv);
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
          } else if (strEq(argLong, "strict")) {
            args.validateStrict = true;
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
        if (strEq(argv[a], "--passphrase-file")) {
          args.exportPassphraseFile = getArgParam(++a, argc, argv);
          break;
        } else if (strEq(argv[a], "--sign-key")) {
          args.exportSignKey = getArgParam(++a, argc, argv);
          break;
        } else if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageExport();
            exit(0);
          case 'o':
            args.exportOutput = getArgParam(++a, argc, argv);
            break;
          case 'P':
            args.exportPassphraseFile = getArgParam(++a, argc, argv);
            break;
          case 'K':
            args.exportSignKey = getArgParam(++a, argc, argv);
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
        if (strEq(argv[a], "--passphrase-file")) {
          args.importPassphraseFile = getArgParam(++a, argc, argv);
          break;
        } else if (strEq(argv[a], "--verify-key")) {
          args.importVerifyKey = getArgParam(++a, argc, argv);
          break;
        } else if (auto argShort = isShort(argv[a])) {
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
          case 'P':
            args.importPassphraseFile = getArgParam(++a, argc, argv);
            break;
          case 'V':
            args.importVerifyKey = getArgParam(++a, argc, argv);
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
      case CmdStack:
        if (strEq(argv[a], "--var")) {
          const char *kv = getArgParam(++a, argc, argv);
          std::string kvs(kv);
          auto eq = kvs.find('=');
          if (eq == std::string::npos)
            err("--var requires KEY=VALUE format, got '%s'", kv);
          args.vars[kvs.substr(0, eq)] = kvs.substr(eq + 1);
          break;
        } else if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageStack();
            exit(0);
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usageStack();
            exit(0);
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else if (args.stackSubcmd.empty()) {
          args.stackSubcmd = argv[a];
          if (args.stackSubcmd != "up" && args.stackSubcmd != "down" &&
              args.stackSubcmd != "status" && args.stackSubcmd != "exec")
            err("unknown stack subcommand '%s'", argv[a]);
        } else if (args.stackFile.empty()) {
          args.stackFile = argv[a];
        } else if (args.stackSubcmd == "exec" && args.stackExecContainer.empty()) {
          args.stackExecContainer = argv[a];
        } else if (args.stackSubcmd == "exec") {
          // Remaining args are the command to execute
          // Handle "--" separator
          if (strcmp(argv[a], "--") == 0) {
            a++;
          }
          for (; a < argc; a++)
            args.stackExecArgs.push_back(argv[a]);
        } else {
          err("too many arguments for 'stack' command");
        }
        break;
      case CmdGui:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h':
            usageGui();
            exit(0);
          case 'j':
            args.guiJson = true;
            break;
          case 'o':
            args.guiOutput = getArgParam(++a, argc, argv);
            break;
          default:
            err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) {
            usageGui();
            exit(0);
          } else if (strEq(argLong, "output")) {
            args.guiOutput = getArgParam(++a, argc, argv);
            break;
          } else {
            err("unsupported long option '%s'", argv[a]);
          }
        } else if (args.guiSubcmd.empty()) {
          args.guiSubcmd = argv[a];
          if (args.guiSubcmd != "list" && args.guiSubcmd != "focus" &&
              args.guiSubcmd != "attach" && args.guiSubcmd != "url" &&
              args.guiSubcmd != "tile" && args.guiSubcmd != "screenshot" &&
              args.guiSubcmd != "resize")
            err("unknown gui subcommand '%s'", argv[a]);
        } else if (args.guiTarget.empty()) {
          args.guiTarget = argv[a];
        } else if (args.guiSubcmd == "resize" && args.guiResolution.empty()) {
          args.guiResolution = argv[a];
        } else {
          err("too many arguments for 'gui' command");
        }
        break;
      case CmdStats:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h': usageStats(); exit(0);
          case 'j': args.statsJson = true; break;
          default: err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageStats(); exit(0); }
          else if (strEq(argLong, "json")) args.statsJson = true;
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.statsTarget.empty()) {
          args.statsTarget = argv[a];
        } else {
          err("too many arguments for 'stats' command");
        }
        break;
      case CmdLogs:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h': usageLogs(); exit(0);
          case 'f': args.logsFollow = true; break;
          case 'n': args.logsTail = Util::toUInt(getArgParam(++a, argc, argv)); break;
          default: err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageLogs(); exit(0); }
          else if (strEq(argLong, "follow")) args.logsFollow = true;
          else if (strEq(argLong, "tail")) args.logsTail = Util::toUInt(getArgParam(++a, argc, argv));
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.logsTarget.empty()) {
          args.logsTarget = argv[a];
        } else {
          err("too many arguments for 'logs' command");
        }
        break;
      case CmdStop:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h': usageStop(); exit(0);
          case 't': args.stopTimeout = Util::toUInt(getArgParam(++a, argc, argv)); break;
          default: err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageStop(); exit(0); }
          else if (strEq(argLong, "timeout")) args.stopTimeout = Util::toUInt(getArgParam(++a, argc, argv));
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.stopTarget.empty()) {
          args.stopTarget = argv[a];
        } else {
          err("too many arguments for 'stop' command");
        }
        break;
      case CmdRestart:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h': usageRestart(); exit(0);
          case 't': args.restartTimeout = Util::toUInt(getArgParam(++a, argc, argv)); break;
          default: err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageRestart(); exit(0); }
          else if (strEq(argLong, "timeout")) args.restartTimeout = Util::toUInt(getArgParam(++a, argc, argv));
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.restartTarget.empty()) {
          args.restartTarget = argv[a];
        } else {
          err("too many arguments for 'restart' command");
        }
        break;
      case CmdTop:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageTop(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageTop(); exit(0); }
          err("unsupported long option '%s'", argv[a]);
        } else {
          err("'top' command takes no arguments");
        }
        break;
      case CmdInterDns:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageInterDns(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageInterDns(); exit(0); }
          err("unsupported long option '%s'", argv[a]);
        } else {
          err("'inter-dns' command takes no arguments");
        }
        break;
      case CmdVpn:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageVpn(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageVpn(); exit(0); }
          err("unsupported long option '%s'", argv[a]);
        } else if (args.vpnSubcmd.empty()) {
          args.vpnSubcmd = argv[a];
        } else if (args.vpnAction.empty()) {
          args.vpnAction = argv[a];
        } else if (args.vpnSpecFile.empty()) {
          args.vpnSpecFile = argv[a];
        } else {
          err("too many arguments for 'vpn' command");
        }
        break;
      case CmdInspect:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageInspect(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageInspect(); exit(0); }
          err("unsupported long option '%s'", argv[a]);
        } else if (args.inspectTarget.empty()) {
          args.inspectTarget = argv[a];
        } else {
          err("too many arguments for 'inspect' command");
        }
        break;
      case CmdMigrate:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageMigrate(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageMigrate(); exit(0); }
          else if (strEq(argLong, "from"))             args.migrateFrom = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "to"))               args.migrateTo = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "from-token-file"))  args.migrateFromTokenFile = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "to-token-file"))    args.migrateToTokenFile = getArgParam(++a, argc, argv);
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.migrateTarget.empty()) {
          args.migrateTarget = argv[a];
        } else {
          err("too many arguments for 'migrate' command");
        }
        break;
      case CmdBackup:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageBackup(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageBackup(); exit(0); }
          else if (strEq(argLong, "output-dir"))         args.backupOutputDir = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "since"))              args.backupSince = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "auto-incremental"))   args.backupAutoIncremental = true;
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.backupTarget.empty()) {
          args.backupTarget = argv[a];
        } else {
          err("too many arguments for 'backup' command");
        }
        break;
      case CmdBackupPrune:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageBackupPrune(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help"))             { usageBackupPrune(); exit(0); }
          else if (strEq(argLong, "keep"))         args.backupPruneKeep = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "jail"))         args.backupPruneJailFilter = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "dry-run"))      args.backupPruneDryRun = true;
          else if (strEq(argLong, "delete-orphans")) args.backupPruneDeleteOrphans = true;
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.backupPruneDir.empty()) {
          args.backupPruneDir = argv[a];
        } else {
          err("too many arguments for 'backup-prune' command");
        }
        break;
      case CmdRestore:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageRestore(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageRestore(); exit(0); }
          else if (strEq(argLong, "to"))   args.restoreDataset = getArgParam(++a, argc, argv);
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.restoreFile.empty()) {
          args.restoreFile = argv[a];
        } else {
          err("too many arguments for 'restore' command");
        }
        break;
      case CmdReplicate:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageReplicate(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageReplicate(); exit(0); }
          else if (strEq(argLong, "to"))                  args.replicateTo = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "dest-dataset"))        args.replicateDestDataset = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "since"))               args.replicateSince = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "auto-incremental"))    args.replicateAutoIncremental = true;
          else if (strEq(argLong, "ssh-port"))            args.replicateSshPort = Util::toUInt(getArgParam(++a, argc, argv));
          else if (strEq(argLong, "ssh-key"))             args.replicateSshKey = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "ssh-config"))          args.replicateSshConfig = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "ssh-opt"))             args.replicateSshOpts.push_back(getArgParam(++a, argc, argv));
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.replicateTarget.empty()) {
          args.replicateTarget = argv[a];
        } else {
          err("too many arguments for 'replicate' command");
        }
        break;
      case CmdTemplate:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageTemplate(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageTemplate(); exit(0); }
          else if (strEq(argLong, "output"))   args.warmOutputDataset = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "promote"))  args.warmPromote = true;
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.templateSubcmd.empty()) {
          args.templateSubcmd = argv[a];
        } else if (args.warmTarget.empty()) {
          args.warmTarget = argv[a];
        } else {
          err("too many arguments for 'template' command");
        }
        break;
      case CmdRetune:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageRetune(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageRetune(); exit(0); }
          else if (strEq(argLong, "rctl"))   args.retunePairs.push_back(getArgParam(++a, argc, argv));
          else if (strEq(argLong, "clear"))  args.retuneClear.push_back(getArgParam(++a, argc, argv));
          else if (strEq(argLong, "show"))   args.retuneShow = true;
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.retuneTarget.empty()) {
          args.retuneTarget = argv[a];
        } else {
          err("too many arguments for 'retune' command");
        }
        break;
      case CmdDoctor:
        if (auto argShort = isShort(argv[a])) {
          switch (argShort) {
          case 'h': usageDoctor(); exit(0);
          case 'j': args.doctorJson = true; break;
          default:  err("unsupported short option '%s'", argv[a]);
          }
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help"))      { usageDoctor(); exit(0); }
          else if (strEq(argLong, "json")) args.doctorJson = true;
          else err("unsupported long option '%s'", argv[a]);
        } else {
          err("'doctor' command takes no positional arguments");
        }
        break;
      case CmdThrottle:
        if (auto argShort = isShort(argv[a])) {
          if (argShort == 'h') { usageThrottle(); exit(0); }
          err("unsupported short option '%s'", argv[a]);
        } else if (auto argLong = isLong(argv[a])) {
          if (strEq(argLong, "help")) { usageThrottle(); exit(0); }
          else if (strEq(argLong, "ingress"))        args.throttleIngressRate = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "ingress-burst"))  args.throttleIngressBurst = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "egress"))         args.throttleEgressRate = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "egress-burst"))   args.throttleEgressBurst = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "queue"))          args.throttleQueue = getArgParam(++a, argc, argv);
          else if (strEq(argLong, "clear"))          args.throttleClear = true;
          else if (strEq(argLong, "show"))           args.throttleShow = true;
          else err("unsupported long option '%s'", argv[a]);
        } else if (args.throttleTarget.empty()) {
          args.throttleTarget = argv[a];
        } else {
          err("too many arguments for 'throttle' command");
        }
        break;
      }
    }
  }

  processed = a;
  return args;
}

