# Діаграми взаємодії контейнерів Crate

## Зміст

1. [Високорівнева взаємодія типів контейнерів](#1-високорівнева-взаємодія-типів-контейнерів)
2. [Мережева архітектура](#2-мережева-архітектура)
3. [Керування диском та сховищем](#3-керування-диском-та-сховищем)
4. [Керування пам'яттю та ресурсами](#4-керування-памяттю-та-ресурсами)
5. [Оркестрація Stack](#5-оркестрація-stack)

---

## 1. Високорівнева взаємодія типів контейнерів

```mermaid
graph TB
    subgraph HOST["🖥️ FreeBSD Host"]
        direction TB
        CRATE["crate CLI"]
        DAEMON["crated daemon"]
        IPFW["ipfw firewall"]
        PF["pf anchors"]
        ZFS["ZFS pool"]
        RCTL["RCTL subsystem"]
    end

    subgraph JAILS["Jail контейнери"]
        J1["Jail A<br/>(Spec)"]
        J2["Jail B<br/>(Spec)"]
        J3["Jail C<br/>(Spec)"]
    end

    subgraph VMS["VM контейнери"]
        VM1["VM A<br/>(bhyve)"]
        VM2["VM B<br/>(libvirt)"]
    end

    %% Host → Jail взаємодія (реалізовано)
    CRATE -->|"jail_setv() API"| J1
    CRATE -->|"jail_setv() API"| J2
    CRATE -->|"jail_setv() API"| J3
    ZFS -->|"dataset mount"| J1
    ZFS -->|"dataset mount"| J2
    RCTL -->|"resource limits"| J1
    RCTL -->|"resource limits"| J2
    IPFW -->|"NAT rules"| J1
    PF -->|"anchor policy"| J2

    %% Host → VM взаємодія (реалізовано)
    CRATE -->|"bhyve/libvirt API"| VM1
    CRATE -->|"bhyve/libvirt API"| VM2

    %% Jail ↔ Jail (реалізовано)
    J1 <-->|"epair bridge ✅"| J2
    J1 <-->|"shared volume ✅"| J3
    J2 <-->|"socat proxy ✅"| J3

    %% Jail ↔ VM (НЕ реалізовано)
    J1 -.-x|"❌ не реалізовано"| VM1
    J2 -.-x|"❌ не реалізовано"| VM2

    %% VM ↔ VM (НЕ реалізовано)
    VM1 -.-x|"❌ ізольовані"| VM2

    style HOST fill:#1a1a2e,color:#eee
    style JAILS fill:#16213e,color:#eee
    style VMS fill:#0f3460,color:#eee
```

### Легенда

| Зв'язок | Статус | Опис |
|---------|--------|------|
| Jail ↔ Jail | ✅ Реалізовано | epair bridge, shared volumes (nullfs), socat proxy |
| Host → Jail | ✅ Реалізовано | jail_setv(), ZFS dataset, RCTL, ipfw/pf |
| Host → VM | ✅ Реалізовано | bhyve/libvirt API |
| Jail ↔ VM | ❌ Відсутнє | Повна ізоляція, немає спільного bridge |
| VM ↔ VM | ❌ Відсутнє | Ізольовані, немає крос-комунікації |

---

## 2. Мережева архітектура

### 2.1 Чотири мережеві режими

```mermaid
graph LR
    subgraph NAT_MODE["Режим NAT (default)"]
        direction TB
        NAT_J["Jail"]
        NAT_EPAIR_B["epairNb<br/>10.0.0.x"]
        NAT_EPAIR_A["epairNa<br/>10.0.0.1"]
        NAT_IPFW["ipfw NAT"]
        NAT_WAN["WAN iface"]

        NAT_J --- NAT_EPAIR_B
        NAT_EPAIR_B --- NAT_EPAIR_A
        NAT_EPAIR_A --- NAT_IPFW
        NAT_IPFW --- NAT_WAN
    end

    subgraph BRIDGE_MODE["Режим Bridge"]
        direction TB
        BR_J["Jail"]
        BR_EPAIR_B["epairNb"]
        BR_EPAIR_A["epairNa"]
        BR_BRIDGE["if_bridge"]
        BR_PHYS["Фіз. iface"]

        BR_J --- BR_EPAIR_B
        BR_EPAIR_B --- BR_EPAIR_A
        BR_EPAIR_A --- BR_BRIDGE
        BR_BRIDGE --- BR_PHYS
    end

    subgraph PASSTHROUGH_MODE["Режим Passthrough"]
        direction TB
        PT_J["Jail"]
        PT_NIC["Фіз. NIC<br/>(виділений)"]

        PT_J --- PT_NIC
    end

    subgraph NETGRAPH_MODE["Режим Netgraph"]
        direction TB
        NG_J["Jail"]
        NG_EIFACE["ng eiface"]
        NG_BRIDGE["ng_bridge"]
        NG_PHYS["Фіз. iface"]

        NG_J --- NG_EIFACE
        NG_EIFACE --- NG_BRIDGE
        NG_BRIDGE --- NG_PHYS
    end
```

### 2.2 Мережева взаємодія в Stack

```mermaid
graph TB
    subgraph STACK["Stack: multi-container"]
        direction TB

        subgraph NET["Named Network: app-net"]
            BRIDGE["if_bridge<br/>subnet: 172.20.0.0/24"]
        end

        subgraph CONTAINERS["Контейнери"]
            C_WEB["web<br/>(nginx)"]
            C_APP["app<br/>(node)"]
            C_DB["db<br/>(postgres)"]
        end

        C_WEB -->|"epair → bridge"| BRIDGE
        C_APP -->|"epair → bridge"| BRIDGE
        C_DB -->|"epair → bridge"| BRIDGE

        subgraph DNS_RESOLVE["DNS резолвінг"]
            HOSTS["/etc/hosts<br/>інжекція"]
        end

        HOSTS -.->|"web → 172.20.0.2"| C_WEB
        HOSTS -.->|"app → 172.20.0.3"| C_APP
        HOSTS -.->|"db → 172.20.0.4"| C_DB
    end

    subgraph FIREWALL["Firewall шари"]
        FW_IPFW["ipfw<br/>IN: 10000-29999<br/>OUT: 50000-64999"]
        FW_PF["pf anchor<br/>per-container"]
        FW_SLOT["FwSlots<br/>динамічний розподіл"]
    end

    BRIDGE --> FW_IPFW
    FW_IPFW --> FW_PF
    FW_SLOT -.->|"allocate"| FW_IPFW

    style NET fill:#1b4332,color:#eee
    style FIREWALL fill:#4a1942,color:#eee
```

### 2.3 Мережа — що реалізовано і що відсутнє

| Функція | Статус | Деталі |
|---------|--------|--------|
| NAT через epair + ipfw | ✅ | `run_net.cpp::createEpair()` |
| Bridge (if_bridge) | ✅ | `run_net.cpp::createBridgeEpair()` |
| Passthrough (фіз. NIC) | ✅ | `run_net.cpp::passthroughInterface()` |
| Netgraph (ng_bridge) | ✅ | `run_net.cpp::createNetgraphInterface()` |
| IPv6 (NAT ULA, SLAAC, static) | ✅ | Повна підтримка |
| VLAN 802.1Q | ✅ | ID 1-4094 |
| Статичний MAC (SHA-256) | ✅ | `run_net.cpp::generateStaticMac()` |
| Port forwarding (TCP/UDP) | ✅ | ipfw redirect rules |
| pf anchor per-container | ✅ | `run_net.cpp::setupPfAnchor()` |
| Stack bridge creation | ✅ | `stack.cpp` bridge setup |
| /etc/hosts DNS інжекція | ✅ | `stack.cpp` hosts generation |
| **Вбудований DNS-сервіс для стеків** | ❌ | Тільки /etc/hosts, немає unbound per-stack |
| **Мережеві політики container↔container** | ❌ | Немає allow/deny правил між контейнерами |
| **Jail ↔ VM мережа** | ❌ | Повна ізоляція, немає спільного bridge |
| **Мульти-bridge маршрутизація** | ❌ | Один bridge на stack network |
| **Автоматичний IP-пул** | ❌ | Немає авто-призначення IP з пулу |
| **Нативний IPFW API (IP_FW3)** | ❌ | Використовується ipfw(8) через shell |

---

## 3. Керування диском та сховищем

```mermaid
graph TB
    subgraph ZFS_LAYER["ZFS підсистема"]
        POOL["ZFS Pool"]
        SNAP["Snapshots<br/>create/rollback/destroy"]
        CLONE["Clones"]
        ENCRYPT["Encryption<br/>AES-256-GCM"]
        SEND_RECV["Send/Recv<br/>export/import"]
    end

    subgraph COW["Copy-on-Write"]
        COW_ZFS["ZFS CoW<br/>(ephemeral/persistent)"]
        COW_UNION["unionfs CoW"]
    end

    subgraph MOUNTS["Volume Mounts"]
        NULLFS["nullfs<br/>host ↔ jail"]
        NAMED_VOL["Named Volumes<br/>(stack-level)"]
        SHARED_DIR["Shared Dirs"]
        SHARED_FILE["Shared Files"]
    end

    subgraph JAIL_STORAGE["Jail Storage"]
        J_ROOT["/ (rootfs)"]
        J_DATASET["ZFS datasets<br/>(додаткові)"]
    end

    subgraph VM_STORAGE["VM Storage"]
        VM_DISK["Virtual disk<br/>nvme/virtio/ahci"]
        VM_ISO["ISO image"]
    end

    POOL --> SNAP
    POOL --> CLONE
    POOL --> ENCRYPT
    SNAP --> SEND_RECV

    COW_ZFS --> J_ROOT
    COW_UNION --> J_ROOT
    NULLFS --> J_ROOT
    NAMED_VOL --> NULLFS
    POOL --> J_DATASET

    POOL --> VM_DISK

    %% Відсутні зв'язки
    J_ROOT -.-x|"❌ shared storage<br/>не реалізовано"| VM_DISK
    NAMED_VOL -.-x|"❌ VM volumes<br/>не реалізовано"| VM_STORAGE

    subgraph ARCHIVE[".crate архіви"]
        CREATE_ARCH["crate create<br/>→ .crate file"]
        EXPORT_ARCH["crate export<br/>running → .crate"]
        IMPORT_ARCH["crate import<br/>.crate → dataset"]
        SHA256["SHA-256<br/>валідація"]
    end

    SEND_RECV --> EXPORT_ARCH
    SEND_RECV --> IMPORT_ARCH
    SHA256 --> IMPORT_ARCH

    style ZFS_LAYER fill:#1a1a2e,color:#eee
    style COW fill:#16213e,color:#eee
    style MOUNTS fill:#1b4332,color:#eee
    style VM_STORAGE fill:#4a1942,color:#eee
```

### Диск — що реалізовано і що відсутнє

| Функція | Статус | Деталі |
|---------|--------|--------|
| ZFS snapshots (create/rollback/destroy) | ✅ | `zfs_ops.cpp` |
| ZFS clones | ✅ | `zfs_ops.cpp::clone()` |
| ZFS encryption (AES-256-GCM) | ✅ | `zfs_ops.cpp::isEncrypted()` |
| ZFS send/recv (export/import) | ✅ | `zfs_ops.cpp::send()/recv()` |
| CoW: ZFS (ephemeral/persistent) | ✅ | `CowOptions` в spec |
| CoW: unionfs | ✅ | Альтернативний backend |
| nullfs mounts (host ↔ jail) | ✅ | Shared dirs/files |
| Named volumes (stack) | ✅ | `stack.cpp::StackVolume` |
| .crate archive (create/export/import) | ✅ | SHA-256 валідація, OS version check |
| Dataset-to-jail attachment | ✅ | `zfs_ops.cpp::jailDataset()` |
| VM disk (nvme/virtio/ahci) | ✅ | `vm_spec.h` |
| **Disk I/O лімити (readbps/writebps)** | ⚠️ | Визначено в spec, RCTL передає, але enforcement не верифіковано |
| **ZFS квоти per-container** | ❌ | Немає refquota/refreservation per-dataset |
| **Спільне сховище Jail ↔ VM** | ❌ | Ізольовані, немає virtio-9p/NFS bridge |
| **Кешування base.txz** | ❌ | Завантажується щоразу при `create` |

---

## 4. Керування пам'яттю та ресурсами

```mermaid
graph TB
    subgraph RCTL_SYSTEM["RCTL підсистема"]
        direction TB
        RCTL_API["RCTL C API<br/>(preferred)"]
        RCTL_CMD["rctl(8) command<br/>(fallback)"]
    end

    subgraph MEMORY_LIMITS["Ліміти пам'яті"]
        MEMUSE["memoryuse<br/>(фіз. пам'ять)"]
        VMEMUSE["vmemoryuse<br/>(віртуальна)"]
        MEMLOCK["memorylocked"]
        SWAP["swapuse"]
    end

    subgraph CPU_LIMITS["Ліміти CPU"]
        PCPU["pcpu (%%)"]
        CPUTIME["cputime"]
        CPUSET["cpuset<br/>(CPU pinning)"]
    end

    subgraph IO_LIMITS["Ліміти I/O"]
        READBPS["readbps"]
        WRITEBPS["writebps"]
        READIOPS["readiops"]
        WRITEIOPS["writeiops"]
    end

    subgraph PROC_LIMITS["Ліміти процесів"]
        MAXPROC["maxproc"]
        OPENFILES["openfiles"]
        PTY["pseudoterminals"]
    end

    subgraph JAIL_TARGET["Jail контейнер"]
        JAIL["FreeBSD Jail<br/>(JID)"]
    end

    RCTL_API --> JAIL
    RCTL_CMD --> JAIL

    MEMUSE --> RCTL_API
    VMEMUSE --> RCTL_API
    MEMLOCK --> RCTL_API
    SWAP --> RCTL_API
    PCPU --> RCTL_API
    CPUTIME --> RCTL_API
    READBPS --> RCTL_API
    WRITEBPS --> RCTL_API
    MAXPROC --> RCTL_API
    OPENFILES --> RCTL_API

    CPUSET -->|"cpuset(2)"| JAIL

    subgraph SECURITY["Безпека"]
        SECURELEVEL["securelevel<br/>(-1 to 3)"]
        CAPSICUM["Capsicum<br/>sandbox"]
        MAC["MAC<br/>bsdextended/portacl"]
        ENFORCE_STATFS["enforce_statfs<br/>(0-2)"]
    end

    SECURELEVEL --> JAIL
    CAPSICUM --> JAIL
    MAC --> JAIL

    subgraph MISSING["❌ Відсутнє"]
        OOM["OOM detection<br/>trap/devd"]
        MEM_PRESSURE["Memory pressure<br/>monitoring"]
        STATS_CMD["crate stats<br/>real-time"]
        RESTART_POLICY["Restart policies<br/>on-failure/always"]
        DAEMON_METRICS["Per-container<br/>RCTL metrics"]
    end

    style RCTL_SYSTEM fill:#1a1a2e,color:#eee
    style MISSING fill:#5c1a1a,color:#eee
    style SECURITY fill:#1b4332,color:#eee
```

### Ресурси — що реалізовано і що відсутнє

| Функція | Статус | Деталі |
|---------|--------|--------|
| RCTL memory limits (memoryuse, vmemoryuse) | ✅ | `run_jail.cpp::applyRctlLimits()` |
| RCTL CPU limits (pcpu, cputime) | ✅ | Через RCTL API/command |
| CPU pinning (cpuset) | ✅ | `spec.h::cpuset` |
| RCTL process limits (maxproc, openfiles) | ✅ | Через RCTL |
| Securelevel (-1 to 3) | ✅ | jail parameter |
| Capsicum sandboxing | ✅ | `SecurityAdvanced::capsicum` |
| MAC bsdextended/portacl | ✅ | `mac_ops.cpp` (через shell) |
| IPC controls (sysvipc, mqueue) | ✅ | jail parameters |
| Healthcheck monitoring | ✅ | `run.cpp` — periodic test command |
| **I/O лімити enforcement** | ⚠️ | Визначено, передано в RCTL, але не верифіковано |
| **OOM trap detection** | ❌ | Немає обробки SIGKILL/devd при OOM |
| **Memory pressure monitoring** | ❌ | Немає real-time метрик тиску пам'яті |
| **`crate stats` команда** | ❌ | Немає CLI для перегляду метрик |
| **Per-container daemon metrics** | ❌ | `daemon/metrics.cpp:60` — TODO |
| **Restart policies** | ❌ | Немає on-failure/always перезапуску |
| **Нативний MAC ioctl** | ❌ | Використовується ugidfw(8) через shell |

---

## 5. Оркестрація Stack

```mermaid
graph TB
    subgraph STACK_FILE["stack.yaml"]
        STACK_DEF["StackDef<br/>name, version"]
        NETWORKS["networks:<br/>name, bridge, subnet, gw"]
        VOLUMES["volumes:<br/>name, hostPath"]
        ENTRIES["entries:<br/>name, crate, depends, vars"]
    end

    subgraph RESOLUTION["Розв'язання залежностей"]
        DEP_GRAPH["Граф залежностей<br/>(topological sort)"]
        ORDER["Порядок запуску"]
    end

    STACK_DEF --> DEP_GRAPH
    ENTRIES --> DEP_GRAPH
    DEP_GRAPH --> ORDER

    subgraph STARTUP["Послідовний запуск"]
        direction LR
        S1["1. db<br/>(no deps)"]
        S2["2. cache<br/>(no deps)"]
        S3["3. app<br/>(depends: db, cache)"]
        S4["4. web<br/>(depends: app)"]
        S1 --> S3
        S2 --> S3
        S3 --> S4
    end

    ORDER --> S1
    ORDER --> S2

    subgraph NET_SETUP["Налаштування мережі"]
        CREATE_BRIDGE["Створити bridge<br/>per named network"]
        ASSIGN_IP["Призначити IP"]
        INJECT_HOSTS["Інжекція /etc/hosts"]
    end

    NETWORKS --> CREATE_BRIDGE
    CREATE_BRIDGE --> ASSIGN_IP
    ASSIGN_IP --> INJECT_HOSTS

    subgraph VOL_SETUP["Монтування volumes"]
        HOST_PATH["hostPath → jail"]
        NULLFS_MNT["nullfs mount<br/>readonly flag"]
    end

    VOLUMES --> HOST_PATH
    HOST_PATH --> NULLFS_MNT

    subgraph MISSING_STACK["❌ Відсутнє в Stack"]
        NO_IP_POOL["Авто IP pool<br/>з subnet"]
        NO_NET_POLICY["Network policies<br/>між контейнерами"]
        NO_NET_ISOLATE["Ізоляція мережі<br/>між стеками"]
        NO_MIXED["Mixed jail+VM<br/>в одному stack"]
        NO_DNS["Вбудований DNS<br/>замість /etc/hosts"]
    end

    style STACK_FILE fill:#1a1a2e,color:#eee
    style STARTUP fill:#16213e,color:#eee
    style MISSING_STACK fill:#5c1a1a,color:#eee
```

### Stack — що реалізовано і що відсутнє

| Функція | Статус | Деталі |
|---------|--------|--------|
| Залежності (depends) і порядок запуску | ✅ | Topological sort в `stack.cpp` |
| Named networks (bridge per stack) | ✅ | `stack.cpp` bridge creation |
| Named volumes (hostPath mounts) | ✅ | `StackVolume` + nullfs |
| Змінні per-container (vars) | ✅ | `StackEntry::vars` |
| /etc/hosts DNS інжекція | ✅ | `stack.cpp` hosts generation |
| **Автоматичний IP-пул з subnet** | ❌ | IP не призначаються автоматично з пулу |
| **Network policies між контейнерами** | ❌ | Всі контейнери в bridge бачать один одного |
| **Ізоляція мережі між стеками** | ❌ | Немає firewall між різними стеками |
| **Змішані jail + VM в stack** | ❌ | Тільки jail контейнери підтримуються |
| **Вбудований DNS-сервіс** | ❌ | Тільки /etc/hosts, немає service discovery |

---

## Загальна матриця взаємодії

```mermaid
graph LR
    subgraph TYPES["Типи контейнерів"]
        JAIL["Jail"]
        VM["VM"]
        STACK["Stack<br/>(Jail group)"]
    end

    subgraph CHANNELS["Канали взаємодії"]
        NET["Мережа<br/>epair/bridge"]
        VOL["Volumes<br/>nullfs"]
        SOCK["Socket Proxy<br/>socat"]
        IPC["IPC<br/>sysvipc/mqueue"]
    end

    JAIL -->|"✅"| NET
    JAIL -->|"✅"| VOL
    JAIL -->|"✅"| SOCK
    JAIL -->|"✅"| IPC

    VM -->|"✅ tap only"| NET
    VM -->|"❌"| VOL
    VM -->|"❌"| SOCK
    VM -->|"❌"| IPC

    STACK -->|"✅ bridge"| NET
    STACK -->|"✅ named"| VOL
    STACK -->|"❌"| SOCK
    STACK -->|"❌"| IPC
```

| | Jail ↔ Jail | Jail ↔ VM | VM ↔ VM | Stack (Jail) |
|---|:---:|:---:|:---:|:---:|
| **Мережа** | ✅ epair/bridge | ❌ | ❌ | ✅ bridge |
| **Volumes** | ✅ nullfs | ❌ | ❌ | ✅ named vol |
| **Socket proxy** | ✅ socat | ❌ | ❌ | ❌ |
| **IPC** | ✅ sysvipc | ❌ | ❌ | ❌ |
| **DNS** | ✅ /etc/hosts | ❌ | ❌ | ✅ /etc/hosts |
| **Firewall** | ✅ ipfw+pf | ❌ | ❌ | ✅ ipfw |
| **Resource limits** | ✅ RCTL | ✅ bhyve params | ✅ bhyve params | ✅ RCTL per-jail |
