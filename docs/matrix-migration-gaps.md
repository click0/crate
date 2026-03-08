# Matrix Synapse migration to crate: gap analysis

Analysis of what works well and what's missing in crate for running a production
Matrix Synapse stack (compared to the monolithic `deploy_matrix.sh` approach).

## What works well

### Container isolation
Each service group runs in its own FreeBSD jail with minimal attack surface.
PostgreSQL, Synapse, nginx, and coturn are isolated from each other and from
the host system. A compromise in one container doesn't directly affect others.

### Bridge networking
`bridge99` provides a private L2 network (10.99.0.0/24) between containers.
Static IPs allow predictable addressing. Only nginx and coturn expose ports
to the outside — Synapse is internal-only.

### Stack orchestration
`crate stack up/down/status` manages all three containers together.
`depends: [synapse]` ensures PostgreSQL and Synapse are ready before nginx
starts proxying. Topological sort handles startup ordering.

### Data persistence
`dirs: share` maps container paths to host directories, so all data survives
container recreation. Database, media store, configs, TLS certificates, and
Element Web files are all persistent.

### Variable substitution
`vars` in the stack file pass secrets (DB_PASSWORD, TURN_SECRET, SYNAPSE_SECRET)
and configuration (DOMAIN, SERVER_NAME) consistently across all containers.
Default values (`${VAR:-default}`) reduce required input.

### Healthchecks
Each container has a healthcheck that validates the service is actually
responding (not just that the process is running). Stack can use these to
determine readiness before starting dependent containers.

## Gaps and limitations

### 1. No inter-container DNS

**Impact: Medium**

Containers must use static IPs or `/etc/hosts` entries (injected via scripts)
to reach each other. There is no built-in DNS resolution for container names.

**Workaround**: Add `/etc/hosts` entries in `scripts: run:before-start-services`.
Works but requires manual IP coordination and breaks if IPs change.

**Suggestion**: Add optional DNS resolver to bridge mode that maps container
names from the stack file to their bridge IPs automatically.

### 2. No shared volumes between containers

**Impact: Medium**

Two containers cannot share the same volume directly. For example, certbot
(in the nginx container) generates TLS certificates that coturn also needs.

**Workaround**: Both containers map to the same host directory via `dirs: share`.
This works but requires careful path coordination in the stack file.

**Suggestion**: Support named volumes in stack files that can be mounted into
multiple containers:
```yaml
volumes:
  certs:
    path: $HOME/matrix/certs

containers:
  nginx:
    volumes: [certs:/etc/letsencrypt]
  coturn:
    volumes: [certs:/etc/letsencrypt:ro]
```

### 3. No init/setup phase distinction

**Impact: Medium**

There's no way to distinguish first-run setup (initdb, pip install, certbot
initial) from subsequent runs. All scripts in `run:before-start-services`
execute every time the container starts.

**Workaround**: Guard each setup step with existence checks (`if [ ! -f ... ]`).
This works but makes scripts verbose and error-prone.

**Suggestion**: Add an `init` script phase that runs only on first creation:
```yaml
scripts:
  init:   # runs once after container creation
    - "/usr/local/etc/rc.d/postgresql initdb"
  run:before-start-services:  # runs every start
    - "service postgresql start"
```

### 4. No cron / periodic task support

**Impact: Low-Medium**

No built-in way to schedule periodic tasks inside containers (certbot renewal,
database backups, log rotation).

**Workaround**: Run cron jobs on the host using `crate console` to execute
commands inside containers. Or install and enable cron inside the container
via scripts.

**Suggestion**: Add a `cron` spec section:
```yaml
cron:
  - schedule: "0 3 * * *"
    command: "certbot renew --quiet"
  - schedule: "0 4 * * *"
    command: "pg_dump synapse | gzip > /backup/daily.sql.gz"
```

### 5. No secret management

**Impact: Low-Medium**

Secrets (database passwords, shared secrets) are passed as plain-text vars.
They're visible in process listings, stack files, and shell history.

**Workaround**: Use environment variables and avoid committing stack files
with real secrets. Generate secrets at deploy time.

**Suggestion**: Support secret files or integration with a secrets manager:
```yaml
vars:
  DB_PASSWORD:
    from_file: /root/.matrix_secrets/db_password
```

### 6. No stack-level networking

**Impact: Low**

Bridges must be created manually on the host before running `crate stack up`.
The stack file references `bridge99` but doesn't create it.

**Workaround**: Document bridge creation as a prerequisite. Use a wrapper
script or add to `/etc/rc.conf` for persistence.

**Suggestion**: Allow stack files to define networks:
```yaml
networks:
  matrix:
    bridge: bridge99
    subnet: 10.99.0.0/24
    gateway: 10.99.0.1

containers:
  synapse:
    network: matrix
    ip: 10.99.0.2
```

### 7. No logging aggregation

**Impact: Low**

Each container has isolated logs. Viewing logs requires `crate console` into
each container or accessing shared directories.

**Workaround**: Share log directories to the host via `dirs: share` and use
standard host-side tools (tail, less) to view them.

### 8. No UDP port ranges in inbound rules

**Impact: Low**

coturn needs UDP ports 49152-65535 for media relay. Individual port forwarding
rules don't support ranges efficiently.

**Workaround**: Use bridge mode where the container has its own IP and all
ports are directly accessible. This is the current approach.

### 9. No hot-reload / config update

**Impact: Low**

Changing configuration (e.g., updating nginx config, Synapse settings) requires
recreating the container. There's no `crate reload` or config-only update.

**Workaround**: Edit config files in shared host directories, then
`crate console <container> -- service <svc> reload`.

### 10. Firewall not containerized

**Impact: Informational**

The original script configures host-level IPFW rules. This is inherently a
host concern and cannot be containerized. crate's `options: net` handles
port forwarding, but production deployments still need host-level firewall
configuration for security.

**Note**: This is not a gap — it's correct that firewall stays on the host.
Document required firewall rules alongside the stack deployment instructions.

## Coverage mapping

| Original script phase | crate coverage | Notes |
|----------------------|----------------|-------|
| Phase 1: System prep | Container pkg install | Handled per-container |
| Phase 2: Network | bridge99 + `options: net` | Manual bridge setup required |
| Phase 3: PostgreSQL | matrix-synapse scripts | initdb + tuning in scripts |
| Phase 4: Synapse | matrix-synapse scripts | virtualenv + config generation |
| Phase 5: Nginx | matrix-nginx scripts | Full config + Element Web |
| Phase 6: TLS | matrix-nginx (certbot) | Manual certbot step |
| Phase 7: coturn | matrix-coturn scripts | Standalone container |
| Phase 8: Element Web | matrix-nginx scripts | Downloaded at first start |
| Phase 9: Admin user | Manual post-deploy | `crate console` command |
| Phase 10: .well-known | matrix-nginx config | Served by nginx |
| Phase 11: Monitoring | matrix-health.sh | Host-side script |
| Phase 12: Backup | matrix-backup.sh | Host-side script |

## Summary

crate provides solid foundations for containerizing Matrix Synapse: jail
isolation, bridge networking, stack orchestration with dependency ordering,
persistent storage, and healthchecks all work well.

The main gaps are quality-of-life features: inter-container DNS, shared volumes,
init vs. run script distinction, and secret management. All have functional
workarounds. The deployment works today — these improvements would make it
cleaner and more maintainable.
