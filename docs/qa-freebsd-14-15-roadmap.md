# QA роадмап для FreeBSD 14.x та 15.x

## Відмінності між FreeBSD 14.x і 15.x, критичні для Crate

### Зведена таблиця відмінностей

| Компонент | FreeBSD 14.x | FreeBSD 15.x | Вплив на Crate |
|-----------|-------------|-------------|----------------|
| Jail API | `jail_setv()` → JID | `jail_setv(JAIL_OWN_DESC)` → FD | Два code path в `run_jail.cpp` |
| Jail removal | `jail_remove(jid)` | `jail_remove_jd(fd)` | Race condition fix на 15.x |
| Epair offload | TCP checksum працює | Bug з txcsum на epair | Workaround: `-txcsum -txcsum6` |
| ipfw compat | Legacy ipfw доступний | Legacy ipfw видалено | Потенційний breaking change |
| MNT_IGNORE | Доступний | Доступний | devfs mount прихований від df |
| VM audio | Немає virtio-sound | virtio-sound підтримується | Нова опція в 15.x |
| libpfctl | 14.0+ доступний | Покращений | Firewall operations |
| sys/jail.h | Без JAIL_OWN_DESC | JAIL_OWN_DESC визначений | `#ifdef` guard |

---

## Рівень Q1: Compile-Time Verification

### Q1.1 Компіляція на обох версіях

**Мета:** Гарантувати що код компілюється без warnings на 14.x і 15.x

```
Тести:
Q1.1.1  make clean && make -j$(sysctl -n hw.ncpu) 2>&1 | grep -c warning → 0
Q1.1.2  make clean && make HAVE_LIBZFS=1 → OK
Q1.1.3  make clean && make WITH_LIBVIRT=1 → OK
Q1.1.4  make clean && make HAVE_CAPSICUM=1 → OK
Q1.1.5  Всі optional features одночасно → OK
```

**FreeBSD-специфічне:**
```
Q1.1.6  [14.x] JAIL_OWN_DESC НЕ визначений → компіляція OK, fallback code path
Q1.1.7  [15.x] JAIL_OWN_DESC визначений → компіляція OK, descriptor code path
Q1.1.8  [14.x] jail_remove_jd символ ВІДСУТНІЙ у бінарнику
Q1.1.9  [15.x] jail_remove_jd символ ПРИСУТНІЙ у бінарнику
```

### Q1.2 Header compatibility

```
Q1.2.1  #include <sys/jail.h> в C++ → компілюється (extern "C" guard)
Q1.2.2  #include <sys/mount.h> → MNT_IGNORE доступний
Q1.2.3  [14.x] #include <net/if.h> → epair ioctl
Q1.2.4  [15.x] #include <net/if.h> → epair ioctl + offload flags
```

### Q1.3 Feature flag matrix

```
                        │ 14.2    │ 15.0    │
────────────────────────┼─────────┼─────────┤
HAVE_LIBZFS             │ ✅ test │ ✅ test │
HAVE_LIBIFCONFIG        │ ✅ test │ ✅ test │
HAVE_LIBPFCTL           │ ✅ test │ ✅ test │
HAVE_CAPSICUM           │ ✅ test │ ✅ test │
WITH_LIBVIRT            │ ✅ test │ ✅ test │
WITH_LIBVNCSERVER       │ ✅ test │ ✅ test │
WITH_X11                │ ✅ test │ ✅ test │
WITH_LIBSEAT            │ ✅ test │ ✅ test │
Без optional features   │ ✅ test │ ✅ test │
Всі optional features   │ ✅ test │ ✅ test │
```

---

## Рівень Q2: Jail API тести

### Q2.1 Створення/видалення jail

```
Q2.1.1  [14.x] jail_setv(JAIL_CREATE) → повертає JID > 0
Q2.1.2  [15.x] jail_setv(JAIL_CREATE|JAIL_OWN_DESC) → повертає JID > 0, desc → FD
Q2.1.3  [14.x] jail_remove(jid) → 0 (success)
Q2.1.4  [15.x] jail_remove_jd(fd) → 0 (success)
Q2.1.5  [15.x] close(fd) після jail_remove_jd → OK (double-free safe)
```

### Q2.2 Race condition тести (15.x focus)

```
Q2.2.1  Створити 100 jail швидко → всі створені, всі видалені
Q2.2.2  Паралельне створення/видалення → немає zombie jail
Q2.2.3  [15.x] FD leak test: створити 1000 jail → перевірити fd count
Q2.2.4  [14.x] JID reuse test: створити/видалити → JID може бути reused
```

### Q2.3 Jail параметри

```
Q2.3.1  persist → jail залишається після exit
Q2.3.2  allow.raw_sockets → ping працює
Q2.3.3  allow.socket_af → socket creation
Q2.3.4  allow.sysvipc → IPC працює
Q2.3.5  allow.mount + allow.mount.zfs → ZFS в jail
Q2.3.6  enforce_statfs=2 → тільки jail fs видимі
Q2.3.7  vnet → мережева ізоляція
Q2.3.8  securelevel=1 → обмеження діють
Q2.3.9  children.max → обмеження вкладених jail
Q2.3.10 [14.x+15.x] Всі параметри одночасно → OK
```

---

## Рівень Q3: Мережеві тести

### Q3.1 Epair тести

```
Q3.1.1  [14.x] Створити epair → ping → OK
Q3.1.2  [15.x] Створити epair → ping → OK
Q3.1.3  [15.x] Створити epair без -txcsum → checksums corrupt → ping fails
Q3.1.4  [15.x] Створити epair з -txcsum -txcsum6 → ping → OK
Q3.1.5  [14.x] -txcsum не шкодить (нейтральний) → ping → OK
Q3.1.6  100 epair pairs → всі працюють → всі видалені
```

### Q3.2 NAT тести

```
Q3.2.1  [14.x] ipfw NAT → jail → curl httpbin.org → OK
Q3.2.2  [15.x] ipfw NAT → потенційний breaking change!
Q3.2.3  Port forwarding TCP → host:8080 → jail:80
Q3.2.4  Port forwarding UDP → host:53 → jail:53
Q3.2.5  Multiple port ranges → всі працюють
Q3.2.6  Outbound rules: WAN=allow, LAN=deny → правильна фільтрація
```

**⚠️ КРИТИЧНО для 15.x:**
```
Q3.2.7  [15.x] Перевірити ipfw compatibility layer
Q3.2.8  [15.x] Якщо legacy ipfw видалений → pf fallback працює?
Q3.2.9  [15.x] IP_FW3 setsockopt → працює без legacy ipfw?
```

### Q3.3 Bridge тести

```
Q3.3.1  Bridge з 2 jail → ping між ними → OK
Q3.3.2  Bridge з 5 jail → mesh connectivity
Q3.3.3  Bridge + DHCP → IP отримано
Q3.3.4  Bridge + static IP → правильна адреса
Q3.3.5  Bridge + VLAN → трафік тегований
Q3.3.6  Bridge + static MAC → правильний MAC
Q3.3.7  [14.x + 15.x] Однакова поведінка bridge
```

### Q3.4 Passthrough/Netgraph тести

```
Q3.4.1  Passthrough: фізичний NIC в jail → працює
Q3.4.2  Netgraph: ng_bridge + ng_eiface → працює
Q3.4.3  [14.x] Netgraph node cleanup
Q3.4.4  [15.x] Netgraph node cleanup (змінений API?)
```

### Q3.5 IPv6 тести

```
Q3.5.1  NAT ULA → jail → IPv6 connectivity
Q3.5.2  SLAAC → автоматична IPv6 адреса
Q3.5.3  Static IPv6 → правильна адреса
Q3.5.4  Dual-stack (IPv4 + IPv6) → обидва працюють
```

---

## Рівень Q4: ZFS тести

### Q4.1 Базові ZFS операції

```
Q4.1.1  zfs create dataset → OK
Q4.1.2  zfs snapshot → OK
Q4.1.3  zfs rollback → дані відновлені
Q4.1.4  zfs clone → копія даних
Q4.1.5  zfs destroy → cleanup
Q4.1.6  [14.x + 15.x] Однакова поведінка
```

### Q4.2 ZFS в jail

```
Q4.2.1  jailDataset() → dataset видимий в jail
Q4.2.2  unjailDataset() → dataset невидимий
Q4.2.3  mount() в jail → OK
Q4.2.4  [14.x + 15.x] jail + ZFS delegation
```

### Q4.3 ZFS encryption

```
Q4.3.1  Створити encrypted dataset → OK
Q4.3.2  isEncrypted() → true
Q4.3.3  Key load/unload → правильний стан
Q4.3.4  Encrypted send/recv → OK
Q4.3.5  [14.x + 15.x] Encryption key format compatibility
```

### Q4.4 ZFS quotas (Фаза 2)

```
Q4.4.1  setRefquota(dataset, "10G") → OK
Q4.4.2  Запис більше refquota → ENOSPC
Q4.4.3  Видалення refquota → необмежено
Q4.4.4  [14.x + 15.x] quota enforcement
```

### Q4.5 Export/Import

```
Q4.5.1  zfs send → fd → дані передані
Q4.5.2  zfs recv → dataset створений
Q4.5.3  crate export → .crate файл → SHA-256 match
Q4.5.4  crate import → container → дані збережені
Q4.5.5  Cross-version: export на 14.x → import на 15.x → warning
Q4.5.6  Cross-version: export на 15.x → import на 14.x → warning
Q4.5.7  +CRATE.OSVERSION → правильна версія
```

---

## Рівень Q5: RCTL тести

### Q5.1 Базові RCTL

```
Q5.1.1  Prerequisite: kern.racct.enable=1 → sysctl check
Q5.1.2  rctl -a jail:NAME:memoryuse:deny=512M → OK
Q5.1.3  rctl -l jail:NAME → показує правило
Q5.1.4  rctl -u jail:NAME → показує usage
Q5.1.5  Перевищення ліміту → SIGKILL
Q5.1.6  [14.x + 15.x] RCTL enforcement однакова
```

### Q5.2 I/O ліміти (Фаза 2)

```
Q5.2.1  readbps=50M → dd if=/dev/zero → throttled
Q5.2.2  writebps=50M → dd of=file → throttled
Q5.2.3  [14.x] I/O limits → можуть не працювати без kernel config
Q5.2.4  [15.x] I/O limits → перевірити enforcement
Q5.2.5  Verification: rctl -l → правило присутнє
```

### Q5.3 OOM діагностика (Фаза 2)

```
Q5.3.1  memoryuse=10M + malloc 50M → exit 137
Q5.3.2  diagnoseExitReason() → "OOM (memoryuse > 10M)"
Q5.3.3  Log message → містить причину
Q5.3.4  [14.x + 15.x] Exit code 137 однаковий
```

---

## Рівень Q6: Security тести

### Q6.1 Jail isolation

```
Q6.1.1  Jail → не бачить host процеси (ps aux)
Q6.1.2  Jail → не бачить host filesystem (enforce_statfs=2)
Q6.1.3  Jail → не може змінити hostname (без allow.set_hostname)
Q6.1.4  Jail → не може mount (без allow.mount)
Q6.1.5  securelevel=1 → не можна знизити
Q6.1.6  [14.x + 15.x] Ізоляція однакова
```

### Q6.2 MAC framework

```
Q6.2.1  ugidfw deny → файл недоступний
Q6.2.2  ugidfw allow → файл доступний
Q6.2.3  portacl → порт доступний для UID
Q6.2.4  [15.x] /dev/ugidfw ioctl → працює (Фаза 6)
Q6.2.5  [14.x] Shell ugidfw → працює (fallback)
```

### Q6.3 Capsicum

```
Q6.3.1  cap_enter() → sandbox активний
Q6.3.2  Sandbox → не може відкрити нові файли
Q6.3.3  [14.x + 15.x] Capsicum API однаковий
```

### Q6.4 Firewall security

```
Q6.4.1  Default deny → jail не має доступу
Q6.4.2  Explicit allow → тільки дозволені порти
Q6.4.3  NAT → немає прямого доступу до jail
Q6.4.4  [15.x] pf vs ipfw → fallback працює
```

---

## Рівень Q7: Regression тести по версіях

### Q7.1 FreeBSD 14.2 → 15.0 migration

```
Q7.1.1  Container створений на 14.x → запуск на 15.x → warning
Q7.1.2  .crate архів з 14.x → import на 15.x → OK з warning
Q7.1.3  Stack yaml з 14.x → stack up на 15.x → OK
Q7.1.4  ZFS send на 14.x → recv на 15.x → OK
Q7.1.5  Config files (/usr/local/etc/crate.yml) → сумісні
```

### Q7.2 API compatibility

```
Q7.2.1  daemon REST API → однакові endpoints на 14.x і 15.x
Q7.2.2  Prometheus metrics → однаковий формат
Q7.2.3  SNMP MIB → однакові OID
```

### Q7.3 CLI compatibility

```
Q7.3.1  Всі підкоманди → однакова поведінка на 14.x і 15.x
Q7.3.2  --help → однаковий вивід
Q7.3.3  Exit codes → однакові
Q7.3.4  JSON output (--json) → однакова схема
```

---

## CI/CD Pipeline для QA

### GitHub Actions матриця

```yaml
strategy:
  fail-fast: false
  matrix:
    freebsd-version: ['14.2', '15.0']
    test-level: ['compile', 'unit', 'integration', 'e2e']
    feature-flags:
      - ''                    # minimal
      - 'HAVE_LIBZFS=1'      # with ZFS
      - 'HAVE_LIBZFS=1 HAVE_LIBIFCONFIG=1 HAVE_LIBPFCTL=1 HAVE_CAPSICUM=1'  # full
```

### Нічні тести

```yaml
schedule:
  - cron: '0 3 * * *'

jobs:
  nightly:
    matrix:
      freebsd-version: ['14.2', '15.0']
    steps:
      - Fuzzing (30 хвилин)
      - Performance benchmarks
      - Cross-version migration тести
      - Security audit (CIS benchmarks)
```

### Release checklist

```
Перед кожним релізом:
□ Всі Q1–Q7 тести пройдені на FreeBSD 14.2
□ Всі Q1–Q7 тести пройдені на FreeBSD 15.0
□ Cross-version migration тест (14→15, 15→14)
□ Performance regression < 5% від попереднього релізу
□ Security scan: немає нових вразливостей
□ CHANGELOG оновлений
```

---

## Пріоритети QA задач

| # | Задача | Пріоритет | FreeBSD | Зусилля |
|---|--------|-----------|---------|---------|
| Q1 | Compile matrix | 🔴 Критичний | 14+15 | 2h |
| Q2.1 | Jail create/destroy | 🔴 Критичний | 14+15 | 3h |
| Q2.2 | Race conditions (15.x) | 🔴 Критичний | 15 | 4h |
| Q3.1 | Epair + offload | 🔴 Критичний | 15 | 2h |
| Q3.2 | NAT/ipfw compatibility | 🔴 Критичний | 15 | 6h |
| Q4.5 | Cross-version export/import | 🟡 Високий | 14+15 | 3h |
| Q5.1 | RCTL enforcement | 🟡 Високий | 14+15 | 3h |
| Q6 | Security suite | 🟡 Високий | 14+15 | 8h |
| Q7 | Full regression | 🟢 Середній | 14+15 | 6h |
| Q3.5 | IPv6 | 🟢 Середній | 14+15 | 4h |

### Найбільш ризиковані зони

1. **ipfw на FreeBSD 15.x** — legacy compatibility може бути видалена, потребує pf fallback або IP_FW3 native API
2. **Jail descriptor API** — новий code path на 15.x, потребує ретельного тестування race conditions
3. **Epair checksum offload** — bug в 15.x, workaround може стати непотрібним у майбутніх версіях
4. **Cross-version .crate archives** — ZFS stream format може відрізнятися між 14.x і 15.x
