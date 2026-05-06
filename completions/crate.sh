#!/bin/sh
# Shell completion for crate(1) — FreeBSD jail container tool
# Install: copy to /usr/local/share/crate/completions/crate.sh
# Usage:   . /usr/local/share/crate/completions/crate.sh
#
# Maintenance: when adding a new command, add it to BOTH the bash
# `commands` variable AND the zsh `commands` array below. Auto-gen
# from `crate -h` output is tracked as a future enhancement (D2);
# the current file is hand-maintained against the CLI usage in
# cli/args.cpp.

# Bash completion
if [ -n "$BASH_VERSION" ]; then
  _crate_complete() {
    local cur prev words cword
    _init_completion || return

    local commands="create run list info console clean validate \
                    snapshot export import gui stack stats logs \
                    stop restart top inter-dns vpn inspect migrate \
                    backup restore backup-prune replicate template \
                    retune throttle doctor"
    local global_opts="-h --help -V --version --no-color -p --log-progress"

    case "$prev" in
      crate)
        COMPREPLY=( $(compgen -W "$commands $global_opts" -- "$cur") )
        return
        ;;
      create)
        COMPREPLY=( $(compgen -W "-s --spec -t --template -o --output --use-pkgbase --var -h --help" -- "$cur") )
        return
        ;;
      run)
        COMPREPLY=( $(compgen -W "-f --file --warm-base --name --var -h --help --" -- "$cur") )
        return
        ;;
      validate)
        COMPREPLY=( $(compgen -W "--strict -h --help" -f -X '!*.yml' -- "$cur") )
        return
        ;;
      snapshot)
        COMPREPLY=( $(compgen -W "create list restore delete diff -h --help" -- "$cur") )
        return
        ;;
      export)
        COMPREPLY=( $(compgen -W "-o --output -P --passphrase-file -K --sign-key -h --help" -- "$cur") )
        return
        ;;
      import)
        COMPREPLY=( $(compgen -W "-o --output -f --force -P --passphrase-file -V --verify-key -h --help" -- "$cur") )
        return
        ;;
      list|ls)
        COMPREPLY=( $(compgen -W "-j -h --help" -- "$cur") )
        return
        ;;
      info)
        COMPREPLY=( $(compgen -W "-h --help" -- "$cur") )
        return
        ;;
      console)
        COMPREPLY=( $(compgen -W "-u --user -h --help --" -- "$cur") )
        return
        ;;
      clean)
        COMPREPLY=( $(compgen -W "-n --dry-run -h --help" -- "$cur") )
        return
        ;;
      gui)
        COMPREPLY=( $(compgen -W "list focus attach url tile screenshot resize -j -o --output -h --help" -- "$cur") )
        return
        ;;
      stack)
        COMPREPLY=( $(compgen -W "up down status exec --var -h --help" -- "$cur") )
        return
        ;;
      stats)
        COMPREPLY=( $(compgen -W "-j -h --help" -- "$cur") )
        return
        ;;
      logs)
        COMPREPLY=( $(compgen -W "-f --follow --tail -h --help" -- "$cur") )
        return
        ;;
      stop|restart)
        COMPREPLY=( $(compgen -W "-t --timeout -h --help" -- "$cur") )
        return
        ;;
      top)
        COMPREPLY=( $(compgen -W "-h --help" -- "$cur") )
        return
        ;;
      inter-dns)
        COMPREPLY=( $(compgen -W "-h --help" -- "$cur") )
        return
        ;;
      vpn)
        COMPREPLY=( $(compgen -W "wireguard ipsec render-conf -h --help" -- "$cur") )
        return
        ;;
      inspect)
        COMPREPLY=( $(compgen -W "-h --help" -- "$cur") )
        return
        ;;
      migrate)
        COMPREPLY=( $(compgen -W "--from --to --from-token-file --to-token-file -h --help" -- "$cur") )
        return
        ;;
      backup)
        COMPREPLY=( $(compgen -W "--output-dir --since --auto-incremental -h --help" -- "$cur") )
        return
        ;;
      restore)
        COMPREPLY=( $(compgen -W "--to -h --help" -- "$cur") )
        return
        ;;
      backup-prune)
        COMPREPLY=( $(compgen -W "--keep --jail --dry-run --delete-orphans -h --help" -- "$cur") )
        return
        ;;
      replicate)
        COMPREPLY=( $(compgen -W "--to --dest-dataset --since --auto-incremental --ssh-port --ssh-key --ssh-config --ssh-opt -h --help" -- "$cur") )
        return
        ;;
      template)
        COMPREPLY=( $(compgen -W "warm --output --promote -h --help" -- "$cur") )
        return
        ;;
      retune)
        COMPREPLY=( $(compgen -W "--rctl --clear --show -h --help" -- "$cur") )
        return
        ;;
      throttle)
        COMPREPLY=( $(compgen -W "--ingress --egress --ingress-burst --egress-burst --queue --clear --show -h --help" -- "$cur") )
        return
        ;;
      doctor)
        COMPREPLY=( $(compgen -W "-j --json -h --help" -- "$cur") )
        return
        ;;
      -s|--spec)
        COMPREPLY=( $(compgen -f -X '!*.yml' -- "$cur") )
        return
        ;;
      -t|--template)
        local templates=""
        for t in ~/.config/crate/templates/*.yml /usr/local/share/crate/templates/*.yml; do
          [ -f "$t" ] && templates="$templates $(basename "$t" .yml)"
        done
        COMPREPLY=( $(compgen -W "$templates" -- "$cur") )
        return
        ;;
      -o|--output|-f|--file|-P|--passphrase-file|-K|--sign-key|-V|--verify-key|--from-token-file|--to-token-file|--ssh-key|--ssh-config|--output-dir)
        COMPREPLY=( $(compgen -f -- "$cur") )
        return
        ;;
    esac

    # Default: complete with files
    case "$cur" in
      -*)
        COMPREPLY=( $(compgen -W "$global_opts" -- "$cur") )
        ;;
      *)
        COMPREPLY=( $(compgen -f -- "$cur") )
        ;;
    esac
  }
  complete -F _crate_complete crate
fi

# ZSH completion
if [ -n "$ZSH_VERSION" ]; then
  _crate() {
    local -a commands=(
      'create:create a container from a spec file'
      'run:run a containerized application'
      'list:list running crate containers'
      'info:show detailed container info'
      'console:open a shell in a running container'
      'clean:clean up orphaned resources'
      'validate:validate a crate spec file'
      'snapshot:manage ZFS snapshots'
      'export:export a running container'
      'import:import a crate archive'
      'gui:manage GUI sessions'
      'stack:manage multi-container stacks'
      'stats:show resource usage stats'
      'logs:show container logs'
      'stop:stop a running container'
      'restart:restart a running container'
      'top:live resource monitor'
      'inter-dns:rebuild .crate DNS zone'
      'vpn:VPN config tooling (wireguard, ipsec)'
      'inspect:print full JSON snapshot of container state'
      'migrate:move container between hosts via F2 API'
      'backup:take a ZFS-send stream of a jail'
      'restore:replay a backup stream into a fresh dataset'
      'backup-prune:apply Proxmox-style retention to .zstream files'
      'replicate:stream a ZFS snapshot to a remote host via ssh'
      'template:capture warm template (template warm)'
      'retune:live RCTL adjustment without restart'
      'throttle:dummynet token-bucket network shaping'
      'doctor:health check for crate host'
    )

    _arguments -C \
      '(-h --help)'{-h,--help}'[show help]' \
      '(-V --version)'{-V,--version}'[show version]' \
      '--no-color[disable colored output]' \
      '(-p --log-progress)'{-p,--log-progress}'[log progress]' \
      '1:command:->cmd' \
      '*::arg:->args'

    case "$state" in
      cmd)
        _describe 'command' commands
        ;;
      args)
        case "${words[1]}" in
          create)
            _arguments \
              '(-s --spec)'{-s,--spec}'[spec file]:file:_files -g "*.yml"' \
              '(-t --template)'{-t,--template}'[template name]:template:' \
              '(-o --output)'{-o,--output}'[output file]:file:_files' \
              '--use-pkgbase[use pkgbase bootstrap]' \
              '*--var[KEY=VALUE substitution]:var:' \
              '(-h --help)'{-h,--help}'[show help]'
            ;;
          run)
            _arguments \
              '(-f --file)'{-f,--file}'[crate file]:file:_files -g "*.crate"' \
              '--warm-base[clone from warm-template ZFS dataset]:dataset:' \
              '--name[jail name (with --warm-base)]:name:' \
              '*--var[KEY=VALUE substitution]:var:' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:crate file:_files -g "*.crate"'
            ;;
          validate)
            _arguments \
              '--strict[promote warnings + structural checks to errors]' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:spec file:_files -g "*.yml"'
            ;;
          snapshot)
            _arguments \
              '1:subcommand:(create list restore delete diff)' \
              '2:dataset:' \
              '3:name:' \
              '(-h --help)'{-h,--help}'[show help]'
            ;;
          export)
            _arguments \
              '(-o --output)'{-o,--output}'[output file]:file:_files' \
              '(-P --passphrase-file)'{-P,--passphrase-file}'[passphrase file]:file:_files' \
              '(-K --sign-key)'{-K,--sign-key}'[ed25519 signing key]:file:_files' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:container:'
            ;;
          import)
            _arguments \
              '(-o --output)'{-o,--output}'[output file]:file:_files' \
              '(-f --force)'{-f,--force}'[skip validation]' \
              '(-P --passphrase-file)'{-P,--passphrase-file}'[passphrase file]:file:_files' \
              '(-V --verify-key)'{-V,--verify-key}'[ed25519 verify key]:file:_files' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:archive:_files -g "*.crate"'
            ;;
          list|ls)
            _arguments \
              '-j[output as JSON]' \
              '(-h --help)'{-h,--help}'[show help]'
            ;;
          info|inspect)
            _arguments \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:container:'
            ;;
          console)
            _arguments \
              '(-u --user)'{-u,--user}'[user to login as]:user:_users' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:container:'
            ;;
          clean)
            _arguments \
              '(-n --dry-run)'{-n,--dry-run}'[show what would be cleaned]' \
              '(-h --help)'{-h,--help}'[show help]'
            ;;
          gui)
            _arguments \
              '1:subcommand:(list focus attach url tile screenshot resize)' \
              '-j[output as JSON]' \
              '(-o --output)'{-o,--output}'[output file]:file:_files' \
              '(-h --help)'{-h,--help}'[show help]' \
              '2:target:'
            ;;
          stack)
            _arguments \
              '1:subcommand:(up down status exec)' \
              '*--var[variable substitution]:var:' \
              '(-h --help)'{-h,--help}'[show help]' \
              '2:stack file:_files -g "*.yml"'
            ;;
          stats)
            _arguments \
              '-j[output as JSON]' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:container:'
            ;;
          logs)
            _arguments \
              '(-f --follow)'{-f,--follow}'[stream logs]' \
              '--tail[show last N lines]:N:' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:container:'
            ;;
          stop|restart)
            _arguments \
              '(-t --timeout)'{-t,--timeout}'[stop timeout in seconds]:seconds:' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:container:'
            ;;
          migrate)
            _arguments \
              '--from[source endpoint host:port]:endpoint:' \
              '--to[destination endpoint host:port]:endpoint:' \
              '--from-token-file[source admin token file]:file:_files' \
              '--to-token-file[destination admin token file]:file:_files' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:container:'
            ;;
          backup)
            _arguments \
              '--output-dir[directory for .zstream output]:dir:_directories' \
              '--since[explicit prior snapshot]:snap:' \
              '--auto-incremental[incremental from latest backup-*]' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:jail:'
            ;;
          restore)
            _arguments \
              '--to[destination ZFS dataset]:dataset:' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:stream:_files -g "*.zstream"'
            ;;
          backup-prune)
            _arguments \
              '--keep[retention spec; e.g. daily=7,weekly=4]:spec:' \
              '--jail[filter to one jail]:jail:' \
              '--dry-run[preview without deleting]' \
              '--delete-orphans[delete orphaned incrementals]' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:dir:_directories'
            ;;
          replicate)
            _arguments \
              '--to[remote endpoint user@host or host]:endpoint:' \
              '--dest-dataset[remote ZFS dataset]:dataset:' \
              '--since[explicit prior snapshot]:snap:' \
              '--auto-incremental[incremental from latest replicate-*]' \
              '--ssh-port[ssh port]:port:' \
              '--ssh-key[ssh identity file]:file:_files' \
              '--ssh-config[ssh config file]:file:_files' \
              '*--ssh-opt[extra ssh -o KEY=VAL]:opt:' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:jail:'
            ;;
          template)
            _arguments \
              '1:subcommand:(warm)' \
              '--output[ZFS dataset for the clone]:dataset:' \
              '--promote[zfs promote after clone]' \
              '(-h --help)'{-h,--help}'[show help]' \
              '2:jail:'
            ;;
          retune)
            _arguments \
              '*--rctl[KEY=VALUE]:rule:' \
              '*--clear[KEY to clear]:key:' \
              '--show[dump usage before+after]' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:jail:'
            ;;
          throttle)
            _arguments \
              '--ingress[ingress rate]:rate:' \
              '--egress[egress rate]:rate:' \
              '--ingress-burst[ingress burst bytes]:bytes:' \
              '--egress-burst[egress burst bytes]:bytes:' \
              '--queue[queue size]:slots:' \
              '--clear[drop pipes + binds]' \
              '--show[dump pipe state]' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:jail:'
            ;;
          doctor)
            _arguments \
              '(-j --json)'{-j,--json}'[machine-readable output]' \
              '(-h --help)'{-h,--help}'[show help]'
            ;;
          vpn)
            _arguments \
              '1:subcommand:(wireguard ipsec)' \
              '2:action:(render-conf)' \
              '3:spec file:_files -g "*.yml"' \
              '(-h --help)'{-h,--help}'[show help]'
            ;;
          inter-dns|top)
            _arguments \
              '(-h --help)'{-h,--help}'[show help]'
            ;;
        esac
        ;;
    esac
  }
  compdef _crate crate
fi
