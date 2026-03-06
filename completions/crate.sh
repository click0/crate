#!/bin/sh
# Shell completion for crate(1) — FreeBSD jail container tool
# Install: copy to /usr/local/share/crate/completions/crate.sh
# Usage:   . /usr/local/share/crate/completions/crate.sh

# Bash completion
if [ -n "$BASH_VERSION" ]; then
  _crate_complete() {
    local cur prev words cword
    _init_completion || return

    local commands="create run list info console clean validate snapshot export import gui stack"
    local global_opts="-h --help -V --version --no-color -p --log-progress"

    case "$prev" in
      crate)
        COMPREPLY=( $(compgen -W "$commands $global_opts" -- "$cur") )
        return
        ;;
      create)
        COMPREPLY=( $(compgen -W "-s --spec -t --template -o --output --use-pkgbase -h --help" -- "$cur") )
        return
        ;;
      run)
        COMPREPLY=( $(compgen -W "-f --file -h --help --" -- "$cur") )
        return
        ;;
      validate)
        COMPREPLY=( $(compgen -W "-h --help" -f -X '!*.yml' -- "$cur") )
        return
        ;;
      snapshot)
        COMPREPLY=( $(compgen -W "create list restore delete diff -h --help" -- "$cur") )
        return
        ;;
      export)
        COMPREPLY=( $(compgen -W "-o --output -h --help" -- "$cur") )
        return
        ;;
      import)
        COMPREPLY=( $(compgen -W "-o --output -f --force -h --help" -- "$cur") )
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
        COMPREPLY=( $(compgen -W "list focus attach url tile screenshot resize -h --help" -- "$cur") )
        return
        ;;
      stack)
        COMPREPLY=( $(compgen -W "up down status --var -h --help" -- "$cur") )
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
      -o|--output|-f|--file)
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
              '(-h --help)'{-h,--help}'[show help]'
            ;;
          run)
            _arguments \
              '(-f --file)'{-f,--file}'[crate file]:file:_files -g "*.crate"' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:crate file:_files -g "*.crate"'
            ;;
          validate)
            _arguments \
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
              '(-h --help)'{-h,--help}'[show help]' \
              '1:container:'
            ;;
          import)
            _arguments \
              '(-o --output)'{-o,--output}'[output file]:file:_files' \
              '(-f --force)'{-f,--force}'[skip validation]' \
              '(-h --help)'{-h,--help}'[show help]' \
              '1:archive:_files -g "*.crate"'
            ;;
          list|ls)
            _arguments \
              '-j[output as JSON]' \
              '(-h --help)'{-h,--help}'[show help]'
            ;;
          info)
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
              '1:subcommand:(up down status)' \
              '*--var[variable substitution]:var:' \
              '(-h --help)'{-h,--help}'[show help]' \
              '2:stack file:_files -g "*.yml"'
            ;;
        esac
        ;;
    esac
  }
  compdef _crate crate
fi
