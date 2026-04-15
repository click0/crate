# FreeBSD Self-Hosted GitHub Actions Runner — Setup Guide

This document describes how to set up a **dedicated FreeBSD machine** as a
GitHub Actions self-hosted runner for running Kyua/ATF tests natively
(without QEMU emulation).

## Why a dedicated runner?

The current CI uses `cross-platform-actions/action` to run FreeBSD inside
QEMU on an `ubuntu-latest` GitHub-hosted runner.  This works but has
limitations:

* **Slow** — QEMU emulation adds significant overhead
* **No root/jail access** — cannot test jail creation, networking, ZFS
* **No VIMAGE** — kernel-level network virtualisation is unavailable
* **Timeout-constrained** — 25 min for build+test is tight

A self-hosted FreeBSD runner enables:

* Native speed for compilation and tests
* Root access for integration/E2E tests (jail lifecycle, ipfw, ZFS)
* VIMAGE and kernel module tests
* Longer or unlimited timeouts

---

## 1. Prepare the FreeBSD host

### Minimum requirements

| Resource   | Minimum       | Recommended          |
|------------|---------------|----------------------|
| FreeBSD    | 14.2-RELEASE  | 14.2 + 15.0 (two VMs)|
| CPU        | 2 cores       | 4+ cores             |
| RAM        | 2 GB          | 4+ GB                |
| Disk       | 20 GB         | 50 GB (ZFS pool)     |
| Network    | Internet access| Dedicated VLAN       |

### Install dependencies

```sh
pkg install -y \
    git              \
    kyua             \
    pkgconf          \
    yaml-cpp         \
    rang             \
    bash             \
    curl             \
    jq
```

### Enable VIMAGE (optional, for network tests)

Ensure the kernel has VIMAGE support:

```sh
sysctl kern.features.vimage
# kern.features.vimage: 1
```

If `0` or missing, rebuild the kernel with `options VIMAGE` or use a
FreeBSD version that includes it by default (14.0+).

---

## 2. Create a runner user

```sh
pw useradd -n ghrunner -m -s /usr/local/bin/bash -c "GitHub Actions Runner"
```

For tests that require root (jail creation, ipfw, ZFS), configure
passwordless sudo:

```sh
pkg install -y sudo
echo 'ghrunner ALL=(ALL) NOPASSWD: ALL' > /usr/local/etc/sudoers.d/ghrunner
chmod 0440 /usr/local/etc/sudoers.d/ghrunner
```

---

## 3. Install GitHub Actions Runner

```sh
su - ghrunner

# Download the latest runner (check https://github.com/actions/runner/releases)
RUNNER_VERSION="2.321.0"   # update to latest
curl -fsSL -o actions-runner.tar.gz \
  "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-freebsd-x64-${RUNNER_VERSION}.tar.gz"

mkdir -p ~/actions-runner && cd ~/actions-runner
tar xzf ~/actions-runner.tar.gz
rm ~/actions-runner.tar.gz
```

### Configure the runner

Go to your repository on GitHub:
**Settings → Actions → Runners → New self-hosted runner**

Copy the token and run:

```sh
./config.sh \
  --url https://github.com/click0/crate \
  --token YOUR_TOKEN_HERE \
  --name freebsd-14 \
  --labels freebsd,freebsd-14 \
  --work _work
```

For a second FreeBSD 15 runner, use `--name freebsd-15 --labels freebsd,freebsd-15`.

---

## 4. Run as a service

Create an rc.d script:

```sh
sudo tee /usr/local/etc/rc.d/ghrunner << 'RCEOF'
#!/bin/sh

# PROVIDE: ghrunner
# REQUIRE: NETWORKING LOGIN
# KEYWORD: shutdown

. /etc/rc.subr

name="ghrunner"
rcvar="${name}_enable"
ghrunner_user="ghrunner"
ghrunner_dir="/home/ghrunner/actions-runner"

pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
command_args="-P ${pidfile} -u ${ghrunner_user} -o /var/log/${name}.log ${ghrunner_dir}/run.sh"

load_rc_config $name
: ${ghrunner_enable:=NO}

run_rc_command "$1"
RCEOF

sudo chmod 0555 /usr/local/etc/rc.d/ghrunner
sudo sysrc ghrunner_enable=YES
sudo service ghrunner start
```

Verify:

```sh
sudo service ghrunner status
tail -f /var/log/ghrunner.log
```

---

## 5. Workflow configuration

### Option A: Dedicated self-hosted job

Add a new job in `.github/workflows/freebsd-build.yml` that targets the
self-hosted runner:

```yaml
  test-native:
    runs-on: [self-hosted, freebsd-14]
    timeout-minutes: 60
    steps:
    - uses: actions/checkout@v4

    - name: Build and run Kyua tests
      run: |
        set -ex
        # Unit tests
        ATF_LIBS="-L/usr/local/lib -latf-c++ -latf-c"
        for t in util_test spec_test spec_netopt_test lifecycle_test \
                 network_test network_ipv6_test err_test; do
          c++ -std=c++17 -Ilib -o "tests/unit/${t}" "tests/unit/${t}.cpp" $ATF_LIBS
        done
        chmod +x tests/functional/crate_info_test
        cd tests && sudo kyua test
        sudo kyua report --verbose
        cd ..

    - name: Integration tests (require root)
      run: |
        sudo sh tests/ci-verify.sh .
```

### Option B: Matrix with both QEMU and native

```yaml
jobs:
  build:
    strategy:
      fail-fast: false
      matrix:
        include:
          # QEMU-based (existing, for version coverage)
          - runner: ubuntu-latest
            freebsd-version: '14.2'
            qemu: true
          - runner: ubuntu-latest
            freebsd-version: '15.0'
            qemu: true
          # Native self-hosted (for full test suite)
          - runner: [self-hosted, freebsd-14]
            freebsd-version: '14.2'
            qemu: false
    runs-on: ${{ matrix.runner }}
```

---

## 6. Security considerations

* **Isolate the runner** — use a dedicated VM or jail, not a production host
* **Ephemeral runners** — consider using `--ephemeral` flag so the runner
  de-registers after each job and re-registers fresh
* **Restrict repo access** — only allow this runner for the `crate` repo
* **Firewall** — limit outbound access to GitHub IPs and package mirrors
* **ZFS snapshots** — snapshot the work directory before each job and
  rollback afterwards to ensure clean state

---

## 7. Running tests locally

On any FreeBSD machine with `kyua` installed:

```sh
# Build all unit tests
make test

# Or manually:
cd tests
ATF_LIBS="-L/usr/local/lib -latf-c++ -latf-c"
for t in util_test spec_test spec_netopt_test lifecycle_test \
         network_test network_ipv6_test err_test; do
  c++ -std=c++17 -Ilib -o "unit/${t}" "unit/${t}.cpp" $ATF_LIBS
done
chmod +x functional/crate_info_test

# Run all tests
kyua test

# Verbose report
kyua report --verbose

# Run specific test program
kyua test unit/spec_netopt_test

# Run specific test case
kyua test unit/spec_netopt_test:allowOutbound_all_false
```

---

## 8. Troubleshooting

| Problem | Solution |
|---------|----------|
| `kyua: command not found` | `pkg install kyua` |
| ATF link errors | Check `pkg info -l atf` for library paths, use `-L/usr/local/lib` |
| `AF_INET` / `AF_INET6` undeclared | Add `#include <sys/socket.h>` before `<arpa/inet.h>` |
| Permission denied (jail tests) | Runner needs root or `sudo` access |
| Runner offline on GitHub | Check `service ghrunner status` and `/var/log/ghrunner.log` |
| VIMAGE not available | Rebuild kernel with `options VIMAGE` or use FreeBSD 14+ GENERIC |
