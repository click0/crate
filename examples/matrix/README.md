# Matrix Synapse Stack for crate

Deploys a full Matrix Synapse homeserver across three crate containers:

| Container | Components | Bridge IP |
|-----------|------------|-----------|
| `synapse` | Matrix Synapse + PostgreSQL 16 | 10.99.0.2 |
| `nginx`   | Nginx reverse proxy + Element Web + certbot | 10.99.0.3 |
| `coturn`  | TURN/STUN server for voice/video | 10.99.0.4 |

## Prerequisites

FreeBSD host with crate installed.

### 1. Create bridge network

```sh
ifconfig bridge99 create
ifconfig bridge99 inet 10.99.0.1/24
ifconfig bridge99 up
```

To persist across reboots, add to `/etc/rc.conf`:

```
cloned_interfaces="bridge99"
ifconfig_bridge99="inet 10.99.0.1/24"
```

### 2. Create data directories

```sh
mkdir -p ~/matrix/{synapse,postgres}
mkdir -p ~/matrix/nginx/{conf.d,element,letsencrypt,certbot}
```

### 3. Generate secrets

```sh
export DB_PASSWORD=$(openssl rand -hex 32)
export SYNAPSE_SECRET=$(openssl rand -hex 32)
export TURN_SECRET=$(openssl rand -hex 32)
export EXTERNAL_IPV4=$(ifconfig | grep 'inet ' | grep -v 127.0.0.1 | head -1 | awk '{print $2}')
```

### 4. DNS

Create A (and optionally AAAA) records pointing your domain to the server:

```
matrix.example.com.  A     203.0.113.1
matrix.example.com.  AAAA  2001:db8::1
```

## Deploy

```sh
crate stack up examples/stack-matrix.yml \
  --var DOMAIN=matrix.example.com \
  --var SERVER_NAME=example.com \
  --var DB_PASSWORD=$DB_PASSWORD \
  --var SYNAPSE_SECRET=$SYNAPSE_SECRET \
  --var TURN_SECRET=$TURN_SECRET \
  --var EXTERNAL_IPV4=$EXTERNAL_IPV4
```

Optional variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LE_EMAIL` | (empty) | Email for Let's Encrypt; skips certbot if empty |
| `ENABLE_REGISTRATION` | `false` | Allow public registration |
| `TURN_DOMAIN` | same as DOMAIN | TURN server domain if different |
| `EXTERNAL_IPV6` | (empty) | Public IPv6 for coturn |

## Manage

```sh
# Check status
crate stack status examples/stack-matrix.yml

# Stop all containers
crate stack down examples/stack-matrix.yml

# Health check
./examples/matrix/matrix-health.sh matrix.example.com

# Backup
./examples/matrix/matrix-backup.sh ~/matrix/backups
```

## Create admin user

After the stack is running:

```sh
crate console matrix-synapse -- \
  /var/synapse/venv/bin/register_new_matrix_user \
    -c /var/synapse/homeserver.yaml \
    -u admin -p YOUR_PASSWORD -a \
    http://localhost:8008
```

## TLS certificates

If `LE_EMAIL` was not set during deploy, obtain certificates manually:

```sh
crate console matrix-nginx -- \
  certbot certonly --nginx \
    -d matrix.example.com \
    --email admin@example.com \
    --agree-tos --non-interactive
```

Then update nginx config to use the real certificates:

```sh
# Edit ~/matrix/nginx/conf.d/matrix.conf
# Replace selfsigned.crt/key paths with:
#   /usr/local/etc/letsencrypt/live/matrix.example.com/fullchain.pem
#   /usr/local/etc/letsencrypt/live/matrix.example.com/privkey.pem
```

## Architecture

```
Internet
  │
  ├─ :80/:443/:8448 ──→ [nginx container] ──bridge──→ [synapse container]
  │                       Element Web                   Synapse + PostgreSQL
  │                       certbot/TLS                   :8008 (internal)
  │
  └─ :3478/:5349 ─────→ [coturn container]
                          TURN/STUN relay
```

All containers communicate over `bridge99` (10.99.0.0/24). Only nginx and coturn
expose ports to the outside. Synapse is only accessible via the bridge.

## Data persistence

All data is stored on the host via shared directories:

| Host path | Container path | Contents |
|-----------|---------------|----------|
| `~/matrix/synapse/` | `/var/synapse/` | Config, signing keys, media |
| `~/matrix/postgres/` | `/var/db/postgres/data16/` | PostgreSQL data |
| `~/matrix/nginx/conf.d/` | `/usr/local/etc/nginx/conf.d/` | Nginx config |
| `~/matrix/nginx/element/` | `/var/www/element/` | Element Web files |
| `~/matrix/nginx/letsencrypt/` | `/usr/local/etc/letsencrypt/` | TLS certificates |

## Federation testing

After deployment, test federation at:
https://federationtester.matrix.org/

If `SERVER_NAME` differs from `DOMAIN`, you need to serve `.well-known/matrix/server`
on the `SERVER_NAME` domain pointing to your `DOMAIN`.
