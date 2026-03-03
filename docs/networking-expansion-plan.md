# Networking Expansion Plan: bridge, passthrough, netgraph

> Crate networking expansion inspired by BastilleBSD.
> Status: **Draft** | Target: **0.3.0**

---

## 1. Current State

Crate has a single networking mode: **VNET + epair + automatic NAT**.

| Component | Details |
|---|---|
| Interface | `epair` (auto-created, point-to-point) |
| IP allocation | Automatic from `10.0.0.0/8` (/31 per container, up to ~8M) |
| IPv6 | ULA `fd00:cra7:e::/48` (/126 per container, pass-through, no NAT) |
| NAT | ipfw NAT (automatic rules, per-container `redirect_port`) |
| Firewall | ipfw (NAT + IPv6) + pf anchors (per-container policy) |
| Outbound control | Granular: wan / lan / host / dns |
| DNS | Copy `/etc/resolv.conf` + optional per-jail unbound filtering |
| Cleanup | RAII via `RunAtEnd` destructors, FwSlots for unique rule numbers |

**Key source files:** `lib/run_net.cpp`, `lib/run.cpp:240-620`, `lib/net.cpp`, `lib/spec.h:17-32`

---

## 2. Comparison with BastilleBSD

| Feature | Crate | BastilleBSD | Gap |
|---|---|---|---|
| VNET + epair + NAT | Yes (only mode) | Yes (one of 5+) | — |
| Bridge mode | **No** | Yes (`-B`, if_bridge) | **High** |
| Passthrough mode | **No** | Yes (`-P`, direct iface) | **High** |
| Netgraph | **No** | Yes (ng_bridge) | **Medium** |
| DHCP/SYNCDHCP | **No** | Yes (VNET jails) | **High** |
| SLAAC (IPv6 auto) | **No** | Yes (`accept_rtadv`) | **Medium** |
| Static MAC | **No** | Yes (`-M`, SHA-256 hash) | **High** |
| VLAN | **No** | Yes (`--vlan ID`) | **Medium** |
| Multiple interfaces | **No** | Yes (`network add/remove`) | **Medium** |
| Outbound control (wan/lan/host/dns) | **Yes** | No (manual pf) | Crate leads |
| DNS filtering (unbound) | **Yes** | No | Crate leads |
| Per-container pf anchors | **Yes** | Yes | Parity |
| Automatic ipfw NAT | **Yes** | No | Crate leads |
| Checksum offload workaround (FreeBSD 15) | **Yes** | No | Crate leads |

---

## 3. New Network Modes

### 3.1 Taxonomy

| Mode | Interface | IP addressing | NAT/FW | Use case |
|---|---|---|---|---|
| **nat** (default, current) | epair, auto 10.0.0.0/8 | Static, automatic | ipfw NAT + pf | Isolated containers with internet |
| **bridge** (new) | epair → user's bridge | Static / DHCP / SLAAC | No NAT (L2) | Containers on physical network |
| **passthrough** (new) | physical iface → jail | Static / DHCP / SLAAC | No NAT (L2) | Dedicated NIC per container |
| **netgraph** (new) | ng_bridge + eiface | Static / DHCP / SLAAC | No NAT (L2) | Alternative to if_bridge |

### 3.2 When to Use Each Mode

- **nat** — default for desktop apps, GUI containers, anything that just needs internet access. Simplest, most isolated.
- **bridge** — when the container needs to appear on the physical network (e.g., web server with its own IP, network services). Requires a pre-created bridge.
- **passthrough** — when a physical NIC is dedicated to a single container (e.g., NAS, network appliance). The NIC is exclusively owned by the jail.
- **netgraph** — alternative to bridge for environments where if_bridge has issues or netgraph is preferred. Uses FreeBSD's netgraph subsystem instead of if_bridge.

---

## 4. YAML Configuration Format

### 4.1 Backward Compatibility (existing specs unchanged)

```yaml
# Existing format — works as-is, mode=nat implied
options:
    net:
        outbound: [wan, lan, host, dns]
        inbound-tcp:
            8080: 80
        ipv6: true
```

### 4.2 New Format: Explicit Mode Selection

```yaml
options:
    net:
        mode: bridge               # "nat" (default), "bridge", "passthrough", "netgraph"
        bridge: bridge0            # name of existing bridge (mode=bridge)
        interface: vtnet1          # physical iface (mode=passthrough, mode=netgraph)

        # IP addressing (bridge / passthrough / netgraph only)
        ip: dhcp                   # "dhcp", "192.168.1.50/24", "none"
        gateway: 192.168.1.1      # explicit gateway (not needed with DHCP)
        ip6: slaac                 # "slaac", "fd00::50/64", "none"

        # Cross-mode features
        static-mac: true           # deterministic MAC (bridge/passthrough/netgraph)
        vlan: 100                  # VLAN ID 1-4094

        # Multiple interfaces (optional)
        extra:
            - mode: bridge
              bridge: bridge1
              ip: dhcp
              static-mac: true
            - mode: passthrough
              interface: vtnet2
              ip: none
```

### 4.3 Common Scenarios (Short Forms)

```yaml
# Bridge + DHCP (most common bridge scenario)
options:
    net:
        mode: bridge
        bridge: bridge0
        ip: dhcp

# Passthrough + DHCP + IPv6 SLAAC
options:
    net:
        mode: passthrough
        interface: vtnet1
        ip: dhcp
        ip6: slaac

# Netgraph with static IP
options:
    net:
        mode: netgraph
        interface: em0
        ip: 192.168.1.100/24
        gateway: 192.168.1.1
        static-mac: true

# NAT with bridge as extra interface (mixed modes)
options:
    net:
        outbound: all
        inbound-tcp: [80, 443]
        extra:
            - mode: bridge
              bridge: bridge0
              ip: dhcp
```

### 4.4 Design Principles

- **`mode`** — discriminator. Absent = `nat` (backward compatible)
- **`ip: dhcp`** — single intuitive key instead of BastilleBSD's three variants (0.0.0.0 / DHCP / SYNCDHCP). Crate always uses SYNCDHCP semantics (wait for lease)
- **`outbound`, `inbound-tcp/udp`** — NAT mode only (meaningless for bridge/passthrough since there's no NAT)
- **`extra`** — array of additional interfaces, each with its own settings
- **`ipv6: true`** — keeps existing meaning for NAT mode (ULA); for bridge/passthrough use `ip6: slaac` or static address

---

## 5. Structural Changes

### 5.1 `spec.h` — NetOptDetails

```cpp
class NetOptDetails : public OptDetails {
public:
    // Network mode (NEW)
    enum class Mode { Nat, Bridge, Passthrough, Netgraph };
    Mode mode = Mode::Nat;

    // NAT mode fields (existing, unchanged)
    bool outboundWan, outboundLan, outboundHost, outboundDns;
    bool ipv6;
    std::vector<std::pair<PortRange, PortRange>> inboundPortsTcp;
    std::vector<std::pair<PortRange, PortRange>> inboundPortsUdp;

    // Bridge mode (NEW)
    std::string bridgeIface;          // "bridge0"

    // Passthrough mode (NEW)
    std::string passthroughIface;     // "vtnet1"

    // Netgraph mode (NEW)
    std::string netgraphIface;        // "em0" — physical iface for ng_bridge

    // IP addressing for bridge/passthrough/netgraph (NEW)
    enum class IpMode { Auto, Static, Dhcp, None };
    IpMode ipMode = IpMode::Auto;
    std::string staticIp;             // "192.168.1.50/24"
    std::string gateway;

    // IPv6 for bridge/passthrough/netgraph (NEW)
    enum class Ip6Mode { None, Slaac, Static };
    Ip6Mode ip6Mode = Ip6Mode::None;
    std::string staticIp6;            // "fd00::50/64"

    // Cross-mode features (NEW)
    bool staticMac = false;
    int vlanId = -1;                  // -1 = no VLAN

    // Multiple interfaces (NEW)
    struct ExtraInterface {
        Mode mode;
        std::string bridgeIface, passthroughIface, netgraphIface;
        IpMode ipMode; std::string staticIp, gateway;
        Ip6Mode ip6Mode; std::string staticIp6;
        bool staticMac = false;
        int vlanId = -1;
    };
    std::vector<ExtraInterface> extraInterfaces;

    // Helpers (NEW)
    bool isNatMode() const;
    bool needsIpfw() const;   // NAT only
    bool needsDhcp() const;   // any interface with DHCP
};
```

### 5.2 `run_net.h` — New Structures and Functions

```cpp
namespace RunNet {

// Existing (unchanged)
struct GatewayInfo { std::string iface, hostIP, hostLAN; };
struct EpairInfo { std::string ifaceA, ifaceB, ipA, ipB; unsigned num; };

// NEW structures
struct BridgeInfo {
    std::string ifaceA;       // host-side epair
    std::string ifaceB;       // jail-side epair
    std::string bridgeIface;  // bridge0
    unsigned num;
};

struct PassthroughInfo {
    std::string iface;        // vtnet1 — MUST reclaim before jail destruction
};

struct NetgraphInfo {
    std::string ngIface;      // ng0_<jailname>
    std::string physIface;    // em0
    std::string peerName;     // for ngctl shutdown
};

// NEW functions

// Bridge mode
BridgeInfo createBridgeEpair(int jid, const std::string &jidStr,
    const std::string &bridgeIface,
    const std::function<void(const std::vector<std::string>&,
                              const std::string&)> &execInJail);
void destroyBridgeEpair(const BridgeInfo &info);

// Passthrough mode
PassthroughInfo passthroughInterface(int jid, const std::string &jidStr,
    const std::string &iface);
void reclaimPassthroughInterface(const PassthroughInfo &info, int jid);

// Netgraph mode
NetgraphInfo createNetgraphInterface(int jid, const std::string &jidStr,
    const std::string &physIface,
    const std::function<void(const std::vector<std::string>&,
                              const std::string&)> &execInJail);
void destroyNetgraphInterface(const NetgraphInfo &info);

// Cross-mode utilities
std::pair<std::string,std::string> generateStaticMac(
    const std::string &jailName, const std::string &ifaceName);
void setMacAddress(const std::string &iface, const std::string &mac);
void createVlanInJail(int jid, const std::string &parentIface, int vlanId,
    const std::function<void(const std::vector<std::string>&,
                              const std::string&)> &execInJail);
void configureDhcp(const std::string &jailSideIface,
    const std::string &jailPath, int jid, const std::string &jidStr);
void configureSlaac(const std::string &jailSideIface,
    const std::string &jailPath, int jid, const std::string &jidStr);
void configureStaticIp(const std::string &jailSideIface,
    const std::string &ip, const std::string &gateway, int jid,
    const std::string &jidStr);
void ensureBridgeModule();
void ensureNetgraphModules();
}
```

### 5.3 `config.h` — System-wide Defaults

```cpp
struct Settings {
    // existing...
    std::string networkInterface;       // for NAT mode gateway auto-detect

    // NEW
    std::string defaultBridge;          // default: "" (no default bridge)
    bool staticMacDefault = false;      // default: false
};
```

---

## 6. Implementation Details

### 6.1 Bridge Mode: `createBridgeEpair()`

```
1. ensureKernelModuleIsLoaded("if_bridge")
2. Verify bridge exists: ifconfig bridge0
3. ifconfig epair create → epair3a / epair3b
4. ifconfig epair3a -txcsum -txcsum6   (FreeBSD 15 workaround)
5. ifconfig epair3b -txcsum -txcsum6
6. ifconfig epair3a up
7. ifconfig bridge0 addm epair3a
8. ifconfig epair3b vnet <jid>
9. jexec <jid> ifconfig lo0 inet 127.0.0.1
   (Do NOT assign 10.x.x.x — IP comes from network via DHCP/static)
```

Cleanup:
```
ifconfig bridge0 deletem epair3a
ifconfig epair3a destroy
```

### 6.2 Passthrough Mode: `passthroughInterface()`

```
1. Verify interface exists: ifconfig vtnet1
2. ifconfig vtnet1 vnet <jid>
3. jexec <jid> ifconfig lo0 inet 127.0.0.1
```

Cleanup (**CRITICAL** — must happen BEFORE jail destruction):
```
ifconfig vtnet1 -vnet <jailname>
```

If the jail is destroyed without reclaiming the interface, the physical NIC is **lost until reboot**. This requires special ordering in `run.cpp`:
```cpp
// Passthrough reclaim MUST come before destroyJail!
reclaimPassthroughAtEnd.doNow();  // ← first
destroyJail.doNow();              // ← after
```

### 6.3 Netgraph Mode: `createNetgraphInterface()`

```
1. ensureKernelModuleIsLoaded("ng_ether")
2. ensureKernelModuleIsLoaded("ng_bridge")
3. ensureKernelModuleIsLoaded("ng_eiface")
4. ngctl mkpeer <physIface>: bridge lower link0
5. ngctl mkpeer <bridge>: eiface linkN ether
6. ifconfig <eiface> vnet <jid>
7. jexec <jid> ifconfig lo0 inet 127.0.0.1
```

Cleanup:
```
ngctl shutdown <bridge>:
```

### 6.4 DHCP: `configureDhcp()`

```cpp
// Write to jail's /etc/rc.conf:
appendFile("ifconfig_" + iface + "=\"SYNCDHCP\"\n", jailPath + "/etc/rc.conf");

// Bring interface up
execInJail({"ifconfig", iface, "up"});

// Run dhclient synchronously with timeout
// -T 10 = 10 second lease acquisition timeout
execInJail({"/sbin/dhclient", "-T", "10", iface});
```

DHCP provides its own resolv.conf — do NOT copy host's `/etc/resolv.conf`.

### 6.5 SLAAC: `configureSlaac()`

```cpp
// Write to jail's /etc/rc.conf:
appendFile("ifconfig_" + iface + "_ipv6=\"inet6 -ifdisabled accept_rtadv\"\n", ...);

// Enable IPv6 on the interface
execInJail({"ifconfig", iface, "inet6", "-ifdisabled", "accept_rtadv"});

// Solicit router advertisements
execInJail({"/usr/sbin/rtsol", iface});
```

### 6.6 Static MAC: `generateStaticMac()`

Based on BastilleBSD's `generate_static_mac()`:

```
Prefix:  58:9c:fc (FreeBSD vendor OUI)
Hash:    SHA-256(interfaceName + jailName)
Suffix:  first 5 hex chars of hash → xx:xx:x
Result:  {"58:9c:fc:xx:xx:xa", "58:9c:fc:xx:xx:xb"} (host/jail sides)
```

Requires new utility: `Util::sha256hex()` via FreeBSD `<sha256.h>`.

### 6.7 VLAN: `createVlanInJail()`

```cpp
// Inside jail: create VLAN interface on top of jail-side epair
execInJail({"ifconfig", STR("vlan" << vlanId), "create"});
execInJail({"ifconfig", STR("vlan" << vlanId), "vlan", std::to_string(vlanId),
            "vlandev", parentIface});
```

Requires: `if_vlan` kernel module (usually built into GENERIC).

---

## 7. Orchestration Changes (`run.cpp`)

### 7.1 Current Flow (lines 240-620)

```
if net:
    check VIMAGE → load ipfw_nat → ip.forwarding → detectGateway
    → get nameserver → copy resolv.conf → createEpair (10.0.0.0/8)
    → IPv6 ULA → ipfw rules → pf anchor
```

### 7.2 New Flow with Mode Dispatch

```
if net:
    check VIMAGE   // always (all modes use VNET)

    switch (mode):
      case Nat:
        load ipfw_nat
        enable ip.forwarding
        detectGateway, get nameserver, copy resolv.conf
        createEpair (10.0.0.0/8)
        IPv6 ULA if enabled
        ipfw rules + pf anchor

      case Bridge:
        ensureBridgeModule()
        enable ip.forwarding
        validate bridge exists
        createBridgeEpair()
        if static-mac: setMacAddress()
        if vlan: createVlanInJail()
        configure IP (DHCP / static / none)
        configure IPv6 (SLAAC / static / none)
        pf anchor if firewallPolicy

      case Passthrough:
        validate interface exists
        passthroughInterface()
        if static-mac: setMacAddress()
        if vlan: createVlanInJail()
        configure IP / IPv6
        pf anchor if firewallPolicy

      case Netgraph:
        ensureNetgraphModules()
        enable ip.forwarding
        createNetgraphInterface()
        if static-mac: setMacAddress()
        if vlan: createVlanInJail()
        configure IP / IPv6
        pf anchor if firewallPolicy

    // Extra interfaces (all modes)
    for each extraInterface:
        same mode-dispatch
```

### 7.3 Cleanup Ordering (RAII)

```cpp
// Order matters — reverse of creation, with passthrough special case
RunAtEnd destroyEpipeAtEnd;           // NAT: epair
RunAtEnd destroyBridgeEpairAtEnd;     // Bridge: epair + bridge membership
RunAtEnd reclaimPassthroughAtEnd;     // Passthrough: reclaim BEFORE jail destruction!
RunAtEnd destroyNetgraphAtEnd;        // Netgraph: ng shutdown
RunAtEnd killDhclientAtEnd;           // Bridge/Pass/Ng: kill dhclient
RunAtEnd destroyFirewallRulesAtEnd;   // NAT only
RunAtEnd destroyIpv6FwRules;          // NAT only
RunAtEnd destroyPfAnchor;
RunAtEnd releaseFwSlot;               // NAT only
std::vector<RunAtEnd> destroyExtraInterfaces;
```

### 7.4 Firewall Behavior per Mode

| Aspect | NAT | Bridge | Passthrough | Netgraph |
|---|---|---|---|---|
| ipfw NAT | Yes | No | No | No |
| ipfw_nat module | Yes | No | No | No |
| FwSlots/FwUsers | Yes | No | No | No |
| pf anchor | Yes (epair.ipB) | Yes (jail IP) | Yes (jail IP) | Yes (jail IP) |
| ip.forwarding | Yes | Yes | Optional | Yes |
| DNS filtering | Yes | Optional | Optional | Optional |
| resolv.conf copy | Always | Only if not DHCP | Only if not DHCP | Only if not DHCP |

---

## 8. Kernel Module Requirements

| Mode | Required modules |
|---|---|
| NAT (existing) | `ipfw_nat` |
| Bridge | `if_bridge` (+ `bridgestp` auto-loaded) |
| Passthrough | None additional |
| Netgraph | `ng_ether`, `ng_bridge`, `ng_eiface` |
| VLAN (any mode) | `if_vlan` (usually built into GENERIC) |

All modes require VIMAGE (`kern.features.vimage`).

---

## 9. Validation Rules (`spec.cpp` validate())

| Rule | Condition |
|---|---|
| `mode=bridge` | `bridge` field required |
| `mode=passthrough` | `interface` field required |
| `mode=netgraph` | `interface` field required (physical iface for ng_bridge) |
| `mode=nat` | `bridge`, `interface`, `ip`, `gateway`, `ip6` (as addr), `static-mac` forbidden |
| `outbound`, `inbound-tcp/udp` | NAT mode only |
| `vlan` | bridge/passthrough/netgraph only; range 1-4094 |
| `static-mac` | bridge/passthrough/netgraph only |
| `ip` with CIDR | Requires valid CIDR (e.g., "192.168.1.50/24") |
| `gateway` | Only with static IP |
| `extra` | Each entry validated independently with same rules |

---

## 10. New Utilities

### `util.h/cpp`

```cpp
std::string sha256hex(const std::string &input); // via FreeBSD <sha256.h>
bool interfaceExists(const std::string &ifaceName);
bool isBridgeInterface(const std::string &ifaceName);
std::string parseInetFromIfconfig(const std::string &output);
```

### `pathnames.h`

```cpp
#define CRATE_PATH_DHCLIENT   "/sbin/dhclient"
#define CRATE_PATH_RTSOL      "/usr/sbin/rtsol"
#define CRATE_PATH_NGCTL      "/usr/sbin/ngctl"
```

---

## 11. Implementation Phases

### Phase 1: Bridge Mode + DHCP (highest value)

1. `Mode` enum + `bridgeIface` field in `spec.h`
2. YAML parsing for `mode`, `bridge`, `ip` in `spec.cpp`
3. `ensureBridgeModule()` + `createBridgeEpair()` / `destroyBridgeEpair()` in `run_net.cpp`
4. Mode-dispatch in `run.cpp`
5. `ip` field + `configureDhcp()` for DHCP
6. `configureStaticIp()` for static IP

### Phase 2: Static MAC + VLAN

7. `generateStaticMac()` + `setMacAddress()` in `run_net.cpp`
8. `sha256hex()` in `util.cpp`
9. YAML parsing for `static-mac`, `vlan`
10. `createVlanInJail()` in `run_net.cpp`

### Phase 3: Passthrough Mode

11. Passthrough fields + YAML parsing
12. `passthroughInterface()` / `reclaimPassthroughInterface()`
13. Cleanup ordering fix (reclaim BEFORE jail destruction)

### Phase 4: Netgraph Mode

14. Netgraph fields + YAML parsing
15. `ensureNetgraphModules()` + `createNetgraphInterface()` / `destroyNetgraphInterface()`
16. `ngctl`-based bridge management

### Phase 5: IPv6 SLAAC

17. `ip6` field with SLAAC support
18. `configureSlaac()`
19. `CRATE_PATH_RTSOL`

### Phase 6: Multiple Interfaces

20. `ExtraInterface` struct + `extra` array parsing
21. Loop-based setup/cleanup in `run.cpp`

### Phase 7: System Config + Validation

22. `default_bridge`, `staticMacDefault` in `config.h/cpp`
23. Full cross-validation in `validate()`

---

## 12. Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| DHCP timeout | Container startup hangs | Medium | `dhclient -T 10` (10s timeout), clear error message |
| Lost passthrough iface | Physical NIC lost until reboot | High | RAII cleanup, reclaim BEFORE jail destroy, signal handlers already exist |
| Bridge not created | Container won't start | Low | Clear error: "bridge0 does not exist. Create: `ifconfig bridge0 create; ifconfig bridge0 addm em0; ifconfig bridge0 up`" |
| pf with DHCP | IP unknown until lease | Medium | Apply pf AFTER DHCP, or skip pf for dynamic IP |
| DNS with DHCP | DHCP provides its own resolv.conf | Low | Do not copy host resolv.conf when DHCP is used |
| Netgraph complexity | ngctl API is more complex | Medium | Use `jng` helper script from FreeBSD base if available |
| Multiple interfaces cleanup | Destruction order matters | Medium | `std::vector<RunAtEnd>` in reverse order |
| Bridge security model | Jail on same L2 as host | Low | Opt-in only, documented risk, pf anchors still apply |

---

## 13. Files to Modify

| File | Changes |
|---|---|
| `lib/spec.h` | Mode enum, bridge/passthrough/netgraph fields, IpMode/Ip6Mode enums, ExtraInterface struct |
| `lib/spec.cpp` | YAML parsing for new fields (~line 568-618), validation (~line 315+, ~399+) |
| `lib/run_net.h` | BridgeInfo, PassthroughInfo, NetgraphInfo structs; new function declarations |
| `lib/run_net.cpp` | createBridgeEpair, passthroughInterface, createNetgraphInterface, configureDhcp, configureSlaac, generateStaticMac, createVlanInJail |
| `lib/run.cpp` | Mode-dispatch (lines 240-620), new RunAtEnd variables, extra interfaces loop |
| `lib/net.cpp` | parseInetFromIfconfig() |
| `lib/config.h` | default_bridge, staticMacDefault fields |
| `lib/config.cpp` | YAML parsing for new config fields |
| `lib/util.h/cpp` | sha256hex(), interfaceExists(), isBridgeInterface() |
| `lib/pathnames.h` | CRATE_PATH_DHCLIENT, CRATE_PATH_RTSOL, CRATE_PATH_NGCTL |

---

## 14. Result

After implementation, Crate will have **4 network modes** (nat, bridge, passthrough, netgraph) with support for DHCP, SLAAC, static MAC, VLAN, and multiple interfaces — while keeping configuration as a simple YAML declaration. The existing `mode=nat` behavior remains unchanged — full backward compatibility.
