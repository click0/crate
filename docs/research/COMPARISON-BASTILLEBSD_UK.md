# Crate vs BastilleBSD — Детальне порівняння

> Оновлена версія (березень 2026). Попередні версії: [20250228](COMPARISON-BASTILLEBSD_20250228_UK.md), [v1-pre-2025](COMPARISON-BASTILLEBSD-v1-pre-2025_UK.md).

## Загальний опис

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **Призначення** | Контейнеризатор FreeBSD — пакує застосунки та сервіси в ізольовані самодостатні «крейти» | Система автоматизації розгортання та керування контейнеризованими застосунками на FreeBSD |
| **Мова** | C++17 (~4 000 рядків) | Shell-скрипти (POSIX sh) |
| **Ліцензія** | BSD 3-Clause | BSD |
| **Статус** | Alpha (з 2019, активна розробка) | Стабільний (v1.4.0, активна розробка з 2018) |
| **Філософія** | Мінімалістичні одноразові контейнери для застосунків; акцент на десктопних застосунках та GUI з глибокою ізоляцією | Повнофункціональний менеджер jail-ів для серверів та інфраструктури; DevOps-орієнтований |
| **Залежності** | yaml-cpp, libjail, librang | Лише базова система FreeBSD (sh, jail, zfs, pkg) |

---

## Архітектура та модель роботи

### Crate — «Пакування та запуск»
```
spec.yml → [crate create] → myapp.crate (XZ-архів)
                                  ↓
                            [crate run]
                                  ↓
                    Тимчасовий jail + ZFS COW + мережа + файрвол
                                  ↓
                          Виконання застосунку
                                  ↓
              RAII-очищення (jail, mount, firewall, epair, ZFS)
```
- **Ефемерна модель**: jail створюється під час запуску та знищується після завершення
- 11 команд: `create`, `run`, `validate`, `snapshot`, `list`, `info`, `console`, `clean`, `export`, `import`, `gui`
- Агресивна оптимізація: аналіз ELF-залежностей через ldd, видалення непотрібних файлів
- Контейнер — самодостатній XZ-архів (`.crate`)
- RAII-патерни (RunAtEnd) гарантують очищення навіть при помилках та сигналах

### BastilleBSD — «Створення та керування»
```
bastille bootstrap 14.2-RELEASE → базовий реліз
bastille create myjail 14.2-RELEASE 10.0.0.1 → persistent jail
bastille start/stop/restart myjail → керування життєвим циклом
bastille template myjail user/template → автоматизація налаштування
```
- **Персистентна модель**: jail-и існують тривалий час, керуються як сервіси
- 39 підкоманд для повного керування життєвим циклом
- Jail-и зберігаються на диску (ZFS або UFS)
- Підтримка тонких (thin) та товстих (thick) jail-ів

---

## CLI-команди

### Crate (11 команд)
| Команда | Опис |
|---|---|
| `crate create -s spec.yml -o app.crate` | Створити контейнер зі специфікації |
| `crate create -s spec.yml --template base.yml` | Створити з успадкуванням від шаблону |
| `crate create -s spec.yml --use-pkgbase` | Створити через pkgbase (FreeBSD 16+) |
| `crate run -f app.crate [-- args]` | Запустити контейнер |
| `crate validate -s spec.yml` | Перевірити специфікацію |
| `crate snapshot create\|list\|restore\|delete\|diff` | Керування ZFS-знімками |
| `crate list [-j]` | Перелік запущених контейнерів (таблиця або JSON) |
| `crate info TARGET` | Інформація про запущений контейнер |
| `crate console TARGET [--user USER]` | Інтерактивна оболонка в контейнері |
| `crate clean` | Очищення тимчасових файлів та jail-ів |
| `crate export TARGET [-o FILE]` | Експорт запущеного контейнера в .crate (з SHA256) |
| `crate import FILE [-o FILE] [--force]` | Імпорт .crate з валідацією (SHA256, traversal, OS version) |
| `crate gui list\|focus\|attach\|url\|tile\|screenshot\|resize` | Менеджер GUI-сесій (перемикання, тайлінг, скріншоти) |

### BastilleBSD (39 підкоманд)
| Команда | Опис |
|---|---|
| `bastille bootstrap` | Завантажити реліз FreeBSD/HardenedBSD/MidnightBSD/Linux або шаблон |
| `bastille create` | Створити jail (thin/thick/clone/empty/linux) |
| `bastille start/stop/restart` | Керування запуском |
| `bastille destroy` | Видалити jail або реліз |
| `bastille console` | Увійти до jail (інтерактивна сесія) |
| `bastille cmd` | Виконати команду в jail-і |
| `bastille clone` | Клонувати jail (включно з live через ZFS, `-l`) |
| `bastille rename` | Перейменувати jail |
| `bastille migrate` | Мігрувати jail на віддалений сервер (live для ZFS, `-l`) |
| `bastille export/import` | Експорт/імпорт jail-ів (7 форматів: txz/tgz/tzst/raw/gz/xz/zst; сумісність з iocage, ezjail) |
| `bastille template` | Застосувати шаблон (Bastillefile) до jail-у |
| `bastille pkg` | Керування пакунками (pkg/apt для Linux) |
| `bastille service` | Керування сервісами |
| `bastille mount/umount` | Монтування томів (включно з ZFS mount) |
| `bastille network` | Додати/видалити мережеві інтерфейси (з v0.14) |
| `bastille rdr` | Перенаправлення портів через pf (з IPv6, v1.4) |
| `bastille limits` | Ресурсні обмеження (rctl + cpuset) |
| `bastille list` | Перелік jail-ів, релізів, шаблонів (JSON, пріоритети) |
| `bastille config` | Отримати/встановити властивості jail-у |
| `bastille update/upgrade` | Оновлення jail-у |
| `bastille tags` | Мітки для jail-ів (теги як TARGET) |
| `bastille zfs` | Керування ZFS (snapshot/rollback/jail/unjail/df) |
| `bastille top/htop` | Моніторинг процесів |
| `bastille monitor` | Watchdog сервісів з auto-restart (cron-based, з v1.0) |
| `bastille cp/jcp/rcp` | Копіювання файлів (host↔jail, jail↔jail) |
| `bastille convert` | Конвертація thin↔thick |
| `bastille etcupdate` | Оновлення /etc |
| `bastille verify` | Перевірка релізу |
| `bastille setup` | Автоналаштування хоста (loopback, bridge, vnet, netgraph, firewall, storage, linux) |
| `bastille edit` | Редагування конфігурації jail-у |
| `bastille sysrc` | Безпечне редагування rc-файлів |

**Висновок**: BastilleBSD надає значно ширший набір команд (39) для керування повним життєвим циклом jail-ів. Crate має 11 команд, що охоплюють збирання, запуск, перевірку, керування знімками, перелік, інспекцію, інтерактивну консоль, експорт/імпорт, очищення та керування GUI-сесіями.

---

## Типи jail-ів

| Тип | **Crate** | **BastilleBSD** |
|---|---|---|
| Тонкі (thin/shared base) | Ні — кожен .crate повністю самодостатній | **Так** (типово) — спільна базова система через nullfs |
| Товсті (thick/independent) | Фактично так — кожен .crate містить повну копію | **Так** (прапорець `-T`) |
| Клони (clone) | **Так** (ZFS COW clone під час запуску) | **Так** (прапорець `-C`, ZFS clone; `-l` для live clone) |
| Порожні (empty) | Ні | **Так** (прапорець `-E`) — для власних збірок |
| Linux jail-и | Ні | **Так** (`-L`, Ubuntu Noble/Focal/Bionic, Debian; без VNET) |
| Multi-OS | Лише FreeBSD | **Так** (FreeBSD, HardenedBSD, MidnightBSD, Linux) |

---

## Зберігання даних та ZFS

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **Нативна інтеграція з ZFS** | **Так** | **Так** (підкоманда `zfs`) |
| **ZFS snapshots** | **Так** (`crate snapshot create/list/restore/delete/diff`) | **Так** |
| **ZFS clone (COW)** | **Так** (автоматичний при `cow/backend: zfs`) | **Так** (для тонких jail-ів; live clone через `-l`) |
| **ZFS шифрування** | **Так** (`encrypted: true` в spec, перевірка під час запуску) | Ні (шифрування на рівні пулу) |
| **ZFS datasets в jail** | **Так** (`zfs-datasets:` в YAML, `allow.mount.zfs`) | **Так** (`bastille zfs jail`, v1.0+) |
| **ZFS send/recv** | Ні | **Так** (ZFS snapshot → export → scp на remote; jail працює під час snapshot, але не під час transfer) |
| **Copy-on-Write (COW)** | **Так** (ZFS clone або unionfs, ephemeral/persistent режими) | Через ZFS clone |
| **UFS** | Так (типово) | **Так** |
| **Shared dirs** | Так (nullfs в YAML) | Так (`bastille mount`) |
| **Shared files** | Так (hardlink + fallback mount) | Через mount |
| **Формат контейнера** | `.crate` (XZ-архів) | Каталог на файловій системі |
| **Формати експорту** | `.crate` (XZ) | 7 форматів: `.txz`, `.tgz`, `.tzst`, `.raw`, `.gz`, `.xz`, `.zst` |
| **Оптимізація розміру** | **Так** (ELF-аналіз, видалення зайвого) | Ні (повна система) |
| **ZFS опції при створенні** | Ні | Так (`-Z "compression=lz4,atime=off"`, v0.14+) |
| **pkgbase (FreeBSD 16+)** | **Так** (прапорець `--use-pkgbase`) | **Так** (`bootstrap --pkgbase`) |

**Висновок**: Crate має повноцінну інтеграцію з ZFS, включно зі знімками, COW-клонами, шифруванням та підключенням datasets до jail. BastilleBSD лідирує за ZFS send/recv для міграції та різноманітністю форматів експорту (7 форматів).

---

## Мережа

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **VNET** | **Так** (epair, автоматичне налаштування) | **Так** (5 режимів: -V, -B, -P, alias, inherit) |
| **Мережеві режими** | **4 режими**: NAT, bridge, passthrough, netgraph | **5+ режимів**: -V, -B, -P, alias, inherit + netgraph |
| **NAT** | **Так** (ipfw NAT, автоматична адресація 10.0.0.0/8) | Через pf loopback NAT (`bastille rdr`) |
| **Bridge** | **Так** (`if_bridge`, DHCP або статичний IP, VLAN, static MAC) | **Так** (`-B` — підключення до наявного мосту) |
| **Passthrough** | **Так** (прямий проброс фізичного NIC до контейнера через VNET) | **Так** (`-P` — прямий проброс інтерфейсу, v1.1+) |
| **Netgraph** | **Так** (`ng_bridge` + `eiface`, альтернатива `if_bridge`) | **Так** (`bastille setup netgraph`, v1.0+) |
| **Перенаправлення портів** | **Так** (inbound-tcp/udp в YAML, NAT-режим) | **Так** (`bastille rdr`, +IPv6 у v1.4) |
| **IP-адресація** | NAT: автоматична (10.0.0.0/8); bridge/passthrough/netgraph: DHCP або статичний CIDR | Ручна або DHCP (SYNCDHCP/SLAAC для VNET) |
| **DHCP/SYNCDHCP** | **Так** (синхронне отримання lease для bridge/passthrough/netgraph) | **Так** (для VNET jail-ів, включно з SYNCDHCP) |
| **Статичний IP** | **Так** (CIDR-нотація, напр. `192.168.1.50/24`, з gateway) | **Так** |
| **DNS** | **Опціональна пересилка + DNS-фільтрація** (per-jail unbound) | Через `bastille edit resolv.conf` |
| **Контроль вихідного трафіку** | **Так** (wan/lan/host/dns гранулярність, NAT-режим) | Через правила файрволу (pf/ipfw) |
| **VLAN** | **Так** (802.1Q, ID 1-4094, bridge/passthrough/netgraph) | **Так** (`--vlan ID`, v0.14+) |
| **Static MAC** | **Так** (детерміністичний SHA-256, vendor OUI `58:9c:fc`) | **Так** (прапорець `-M`) |
| **IPv6** | **Так** (NAT ULA fd00:cra7:e::/48, SLAAC для bridge/passthrough/netgraph, статичний IPv6) | **Так** (dual-stack `-D`, SLAAC, IPv6 rdr у v1.4) |
| **Динамічні epair** | **Так** (`ifconfig epair create`, автонумерація) | **Так** (`e0a_jailname`/`e0b_jailname`, v1.0+) |
| **Кілька інтерфейсів** | **Так** (основний + додаткові, кожен з незалежними mode/IP/VLAN) | **Так** (`bastille network add/remove`, v0.14+) |
| **Іменовані мережі** | **Так** (багаторазові мережеві профілі в конфігу, посилання за іменем) | Ні |
| **Checksum offload workaround** | **Так** (FreeBSD 15.0 epair bug) | Немає даних |

**Висновок**: Crate тепер підтримує 4 мережеві режими (NAT, bridge, passthrough, netgraph) з DHCP, статичним IP, VLAN-тегуванням, детерміністичним static MAC, IPv6 (NAT ULA + SLAAC), кількома інтерфейсами на контейнер та іменованими мережевими профілями. BastilleBSD пропонує 5+ мережевих режимів з alias та inherit, а також автоналаштування хоста через `bastille setup`.

---

## Файрвол

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **ipfw** | **Так** (автоматичні NAT правила, IPv4 + IPv6) | Так (ручне налаштування) |
| **pf** | **Так** (per-container pf anchor, §3, з inet6) | **Так** (нативна інтеграція) |
| **Per-container policy** | **Так** (секція `firewall:` в YAML: block_ip, allow_tcp/udp, default_policy) | Через правила pf |
| **Динамічні слоти** | **Так** (FwSlots: унікальні номери правил, без конфліктів, §18) | pf rdr-anchor з таблицями |
| **Перенаправлення портів** | В YAML: `inbound-tcp: {3100: 3000}` | `bastille rdr TARGET tcp 80 8080` |
| **Автоочищення правил** | **Так** (RAII, ref-counting для спільних правил) | `bastille rdr TARGET list/clear` |
| **ip.forwarding** | Автозбереження/відновлення початкового значення (IPv4 + IPv6) | Ручне налаштування |

**Висновок**: Crate підтримує обидва файрволи (ipfw та pf) з підтримкою IPv4 та IPv6, per-container firewall policy через pf anchors та автоматичним керуванням ipfw через динамічні слоти. BastilleBSD орієнтований на pf з повним контролем якорів та таблиць.

---

## Графіка та робочий стіл

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **X11 (shared)** | **Так** (проброс X11-сокета + Xauthority) | Ні (не цільовий сценарій) |
| **X11 (nested/Xephyr)** | **Так** (ізольований вкладений X-сервер, §11) | Ні |
| **X11 (headless/Xvfb)** | **Так** (віртуальний фреймбуфер без фізичного дисплея) | Ні |
| **X11 (GPU headless)** | **Так** (DRM leasing, Xorg з реальним GPU без монітора) | Ні |
| **X11 (disabled)** | **Так** (`mode: none`) | — |
| **VNC** | **Так** (x11vnc з паролем, авто-порт, §gui) | Ні |
| **noVNC/WebSocket** | **Так** (websockify + noVNC для доступу через браузер) | Ні |
| **GUI-менеджер сесій** | **Так** (`crate gui`: list/focus/attach/url/tile/screenshot/resize) | Ні |
| **Ізоляція буфера обміну** | **Так** (режими: isolated/shared/none, напрямок: in/out/both, §12) | Ні |
| **Ізоляція D-Bus** | **Так** (контроль system/session bus, allow_own/deny_send, §13) | Ні |
| **OpenGL/GPU** | **Так** (апаратне прискорення) | Ні |
| **Відеопристрої** | **Так** (проброс /dev/videoN) | Ні |
| **GUI-застосунки** | **Так** (Firefox, Chromium, Kodi тощо) | Ні (серверна орієнтація) |

**Висновок**: Crate унікально позиціонований для запуску десктопних GUI-застосунків у jail-ах: 5 режимів X11 (shared, nested, headless, gpu, none), VNC з паролем, noVNC через браузер, менеджер GUI-сесій з тайлінгом та скріншотами, фільтрація буфера обміну, контроль D-Bus. BastilleBSD орієнтований виключно на серверні навантаження.

---

## Безпека

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **securelevel** | **Налаштовуваний** (-1 auto/0-3, default=2 у config) | **securelevel = 2** типово |
| **enforce_statfs** | **Налаштовуваний** (auto/0/1/2, автовизначення для ZFS) | **2** (фіксований) |
| **devfs_ruleset** | **Налаштовуваний** (§16, terminal isolation) | Ruleset 4 типово; 13 для VNET |
| **RCTL ресурси** | **Так** (будь-які RCTL-ресурси через `limits:` в YAML) | **Так** (через `bastille limits`) |
| **MAC bsdextended** | **Так** (ugidfw правила через `security:` в YAML, §8) | Ні |
| **MAC portacl** | **Так** (mac_portacl через `security:`, §8) | Ні |
| **Capsicum** | **Так** (опція в `security:`, §8) | Ні |
| **raw_sockets** | Налаштовуваний (через секцію ipc:) | **Заборонені** типово |
| **SysV IPC** | Налаштовуваний (`ipc: sysvipc: true`) | Немає даних |
| **allow.mlock** | Налаштовуваний | Немає даних |
| **allow.chflags** | Налаштовуваний | Немає даних |
| **allow.set_hostname** | Налаштовуваний | Немає даних |
| **allow.quotas** | Налаштовуваний | Немає даних |
| **children.max** | **Налаштовуваний** (default=0, як у BastilleBSD) | 0 (заборона вкладених jail) |
| **CPU pinning** | **Так** (cpuset через `security:` в YAML, `/usr/bin/cpuset -l`) | **Так** (cpuset через `bastille limits`) |
| **pathnames.h** | **Так** (абсолютні шляхи до всіх команд, CWE-426, §pathnames) | Bare names (PATH-relative) |
| **Очищення env** | **Так** (environ=empty, відновлення лише TERM/DISPLAY/LANG) | Ні |
| **execv vs execvp** | **Так** (execv — без пошуку по PATH) | execvp/system (через shell) |
| **lstat для symlink** | **Так** (захист від CWE-59) | Немає даних |
| **Jail descriptor** | **Так** (JAIL_OWN_DESC для race-free removal, FreeBSD 15+) | Ні |
| **Archive traversal** | **Так** (перевірка `..` в архівах перед розпакуванням) | Немає даних |
| **Signal-safe cleanup** | **Так** (SIGINT/SIGTERM → RAII destructors) | Через shell trap |
| **Перевірка setuid** | Так (вимагає setuid, заборона запуску з jail) | Так (root) |
| **DNS-фільтрація** | **Так** (per-jail unbound, блокування доменів, §4) | Ні |
| **Socket proxying** | **Так** (socat-based, share/proxy, §15) | Ні |
| **Ізоляція терміналу** | **Так** (devfs ruleset, TTY контроль, §16) | Немає даних |
| **Захист від обходу каталогів** | **Так** (Util::safePath перевірка shared dirs) | Немає даних |

**Висновок**: Crate пропонує значно глибшу багаторівневу модель безпеки: securelevel (налаштовуваний, default=2), children.max (default=0), CPU pinning через cpuset, MAC bsdextended/portacl, Capsicum, DNS-фільтрація, ізоляція буфера обміну та D-Bus, pathnames.h для CWE-426, очищення env, execv, lstat для symlink-атак, JAIL_OWN_DESC для race-free cleanup. BastilleBSD має добрі типові налаштування безпеки (securelevel=2) та ресурсні обмеження.

---

## Шаблонізація та автоматизація

### Crate — YAML-специфікація з успадкуванням шаблонів

```yaml
# spec.yml (§10: шаблони через --template)
pkg:
    install: [firefox, git]
run:
    command: /usr/local/bin/firefox
options: [net, x11, gl, video]

# ZFS шифрування (§1)
encrypted: true

# COW файлова система (§6)
cow:
    backend: zfs        # або unionfs
    mode: ephemeral     # або persistent

# Ресурсні обмеження (§5)
limits:
    memoryuse: 512M
    pcpu: 50
    maxproc: 100

# DNS-фільтрація (§4)
dns:
    block: ["*.ads.example.com", "tracker.example.net"]
    redirect_blocked: nxdomain

# Per-container файрвол (§3)
firewall:
    block_ip: ["192.168.0.0/16"]
    allow_tcp: [80, 443]
    default_policy: block

# Ізоляція X11 (§11)
x11:
    mode: nested        # Xephyr
    resolution: 1920x1080

# Буфер обміну (§12)
clipboard:
    mode: isolated
    direction: out      # лише з jail → host

# D-Bus (§13)
dbus:
    session_bus: true
    system_bus: false
    deny_send: ["org.freedesktop.secrets"]

# Контроль IPC (§7)
ipc:
    sysvipc: false
    raw_sockets: false

# Socket proxying (§15)
sockets:
    share: ["/var/run/dbus/system_bus_socket"]
    proxy:
        - host: /tmp/.X11-unix/X0
          jail: /tmp/.X11-unix/X0

# Розширена безпека (§8)
security:
    capsicum: true
    cpuset: "0-3"
    securelevel: 2
    children_max: 0
    mac_rules: ["subject uid 1001 object not uid 1001 mode rsx"]

# ZFS datasets
zfs-datasets: ["zpool/data/myapp"]

# Хуки життєвого циклу
scripts:
    run:begin: ["echo 'Starting...'"]
    run:after-create-jail: ["setup.sh"]
    run:before-start-services: ["pre-start.sh"]
    run:after-execute: ["cleanup.sh"]
    run:end: ["echo 'Done'"]

dirs:
    share:
        - [/var/db/myapp, $HOME/myapp/db]
```

Успадкування шаблонів (`--template`): шаблонна специфікація зливається з користувацькою через `mergeSpecs()`.

### BastilleBSD — Bastillefile (17 хуків)

```
# Bastillefile
ARG DB_NAME=mydb
ARG+ ADMIN_EMAIL
PKG nginx postgresql15-server
SYSRC nginx_enable=YES
SYSRC postgresql_enable=YES
SERVICE postgresql initdb
SERVICE postgresql start
CMD psql -U postgres -c "CREATE DATABASE ${DB_NAME}"
TEMPLATE /usr/local/etc/nginx/nginx.conf
RENDER /usr/local/etc/nginx/nginx.conf
CP usr/ etc/
LIMITS memoryuse 1G
RDR tcp 8080 80
TAGS web db
```
- Docker-подібний синтаксис з 17 хуками: ARG, ARG+, CMD, CONFIG, CP, INCLUDE, LIMITS, LINE_IN_FILE, MOUNT, PKG, RDR, RENDER, RESTART, SERVICE, SYSRC, TAGS, TEMPLATE
- Обов'язкові аргументи (`ARG+`, v1.4+) — переривання за відсутності
- Вбудовані змінні: `${JAIL_NAME}`, `${JAIL_IP}`, `${JAIL_IP6}`
- Шаблони в Git-репозиторіях з підтримкою підкаталогів (v1.0+)
- Застосовуються до вже створених jail-ів
- Застарілий багатофайловий формат видалено (з v1.2.2)

**Висновок**: Crate описує все в одному YAML-файлі з глибоким налаштуванням безпеки (securelevel, cpuset, children.max, MAC, Capsicum), мережі, ZFS, GUI, DNS та IPC. Підтримує успадкування шаблонів. BastilleBSD використовує Docker-подібний Bastillefile, більш звичний для DevOps-фахівців.

---

## Керування життєвим циклом

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **Створення** | Так (create, +шаблони, +pkgbase) | Так (create, з безліччю опцій) |
| **Запуск** | Так (run, ефемерний) | Так (start) |
| **Зупинка** | Автоматична при виході (RAII) | Так (stop) |
| **Перезапуск** | Ні (перестворення) | Так (restart) |
| **ZFS snapshots** | **Так** (create/list/restore/delete/diff) | **Так** |
| **Клонування** | **Так** (COW під час запуску) | **Так** (clone, включно з live `-l`) |
| **Перейменування** | Ні | Так (rename) |
| **Міграція** | Ні | **Так** (`bastille migrate`: ZFS snapshot → export → scp → import через SSH; `-l` дозволяє export працюючого jail, але є вікно даунтайму при stop/start) |
| **Оновлення ОС** | Перезбирання .crate | Так (update, upgrade, etcupdate) |
| **Експорт/Імпорт** | **Так** (`crate export/import` з SHA256, traversal-валідацією, перевіркою версії ОС) | **Так** (7 форматів, сумісність з iocage/ezjail) |
| **Перелік** | **Так** (`crate list`, таблиця + JSON вивід) | **Так** (list, з пріоритетним сортуванням) |
| **Інспекція** | **Так** (`crate info TARGET`) | Так (`bastille list`, `bastille config`) |
| **Консоль** | **Так** (`crate console TARGET`, jexec-based) | **Так** (`bastille console`) |
| **Моніторинг** | Ні | **Так** (top, htop, monitor з auto-restart, cron-based, v1.0+) |
| **Валідація** | **Так** (`crate validate`) | Так (`bastille verify` для релізів) |
| **Очищення** | **Так** (`crate clean`) | Через `bastille destroy` |
| **Теги** | Ні | Так (tags) |
| **Конвертація** | Ні | Так (thin↔thick, convert) |
| **Копіювання файлів** | Через shared dirs/files | **Так** (cp/jcp/rcp: host↔jail, jail↔jail) |
| **Виявлення невідповідності версій** | **Так** (host vs container FreeBSD version) | Ні |

**Висновок**: Crate має повнофункціональний набір команд: list, info, console, export/import, clean, validate. BastilleBSD надає повний цикл керування jail-ами, включно з live-міграцією, live-клонуванням, моніторингом з auto-restart та копіюванням файлів між jail-ами.

---

## Пакунки та сервіси

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **Встановлення пакунків** | Так (в YAML: pkg.install) | Так (`bastille pkg`) |
| **Локальні пакунки** | Так (pkg.add, pkg.override) | Через cp + pkg |
| **pkgbase** | **Так** (`--use-pkgbase`) | **Так** (`--pkgbase`) |
| **Керування сервісами** | **Так** (run.service + managed services §14) | Так (`bastille service`) |
| **Керовані сервіси** | **Так** (auto-start, auto-stop у зворотному порядку, генерація rc.conf) | Через sysrc + service |
| **Множинні сервіси** | Так | Так |
| **sysrc** | Через managed services rc.conf | **Так** (`bastille sysrc`) |
| **Автоочищення пакунків** | **Так** (видалення невикористаних залежностей) | Ні |
| **Оптимізація (strip)** | **Так** (ELF-аналіз, видалення документації) | Ні |

---

## DNS-фільтрація (унікальна можливість Crate)

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **Per-jail DNS resolver** | **Так** (unbound, §4) | Ні |
| **Блокування доменів** | **Так** (wildcard-патерни) | Ні |
| **Перенаправлення заблокованих** | **Так** (nxdomain або конкретний IP) | Ні |
| **Upstream forwarding** | **Так** (автоматично з resolv.conf хоста) | — |

---

## IPC та ізоляція процесів

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **SysV IPC** | **Налаштовуваний** (§7) | Немає даних |
| **POSIX mqueue** | **Налаштовуваний** (§7) | Немає даних |
| **raw_sockets** | **Налаштовуваний** (override через ipc:) | Заборонені типово |
| **Socket proxying** | **Так** (socat, share/proxy, §15) | Ні |
| **Ізоляція D-Bus** | **Так** (session/system bus, policy, §13) | Ні |
| **Контроль буфера обміну** | **Так** (isolated/shared, direction, §12) | Ні |

---

## Пакетні операції та таргетування

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **Множинні цілі** | Ні (один контейнер) | **Так** — `ALL`, теги, переліки через пробіл |
| **Теги** | Ні | Так (`bastille tags TARGET tag1 tag2`) |
| **Пріоритети завантаження** | Ні | Так (`-p` — порядок старту/зупинки) |
| **Залежності** | Ні | Так (бета: залежний jail автостартує) |
| **JSON вивід** | **Так** (`crate list -j`) | **Так** (`bastille list -j`) |
| **Паралельний запуск** | Ні | Так (`bastille_parallel_limit` у конфігурації) |
| **Затримка запуску** | Ні | Так (`bastille_startup_delay`) |

---

## Автоналаштування хоста

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **Автоналаштування** | Ні (ручне) | **Так** (`bastille setup`: loopback, bridge, vnet, netgraph, firewall, storage, linux) |
| **Налаштування loopback** | Ні | Так (`bastille setup loopback`) |
| **Налаштування bridge** | Ні | Так (`bastille setup bridge`) |
| **Налаштування netgraph** | Ні | Так (`bastille setup netgraph`) |
| **Налаштування firewall** | Ні | Так (`bastille setup firewall`) |
| **Налаштування для Linux** | Ні | Так (`bastille setup linux`) |

**Висновок**: BastilleBSD має унікальну команду `setup`, яка автоматично налаштовує хост-систему для роботи з jail-ами. Crate вимагає ручного налаштування хоста.

---

## Сумісність з OCI/Docker

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **OCI образи** | Ні | **Ні** |
| **Docker Hub** | Ні | Ні |
| **Dockerfile/Containerfile** | Ні | Ні (Bastillefile — власна система) |
| **Формат експорту** | `.crate` (XZ) | 7 форматів (txz/tgz/tzst/raw/gz/xz/zst) |

Обидві системи працюють виключно в екосистемі FreeBSD jail. Для OCI-контейнерів на FreeBSD рекомендується **Podman + ocijail**.

---

## API та вебінтерфейс

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **REST API** | **Так** (`crated` — read-only API: список контейнерів, інфо про хост, GUI-сесії, Prometheus-метрики, health check) | **Так** (bastille-api, JSON payloads, з v1.0) |
| **Prometheus-метрики** | **Так** (`crated` endpoint `/metrics`) | Ні |
| **Вебінтерфейс** | Ні (hub web dashboard заплановано) | **Так** (bastille-ui — Go + HTML, з ttyd-терміналом) |
| **Multi-host агрегатор** | **Так** (`crate-hub` — агрегує метрики з кількох `crated`) | Ні |
| **SNMP** | **Так** (`crate-snmpd` — AgentX subagent, CRATE-MIB) | Ні |
| **Супутні інструменти** | Ні | **Rocinante** — застосовує Bastillefile до хоста |
| **Nomad Driver** | Ні | Заплановано (roadmap 2.0.x) |

---

## Сумісність з FreeBSD 15.0+

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **JAIL_OWN_DESC** | **Так** (race-free jail removal через owning descriptor) | Немає даних |
| **epair checksum fix** | **Так** (disable txcsum/txcsum6 workaround) | Немає даних |
| **Попередження про невідповідність версій** | **Так** (попередження при host ≠ container FreeBSD version) | Немає даних |
| **ipfw compat warning** | **Так** (FreeBSD 15.0 removed old ipfw compat code) | Немає даних |
| **getgroups(2) change** | **Так** (adjusted for setgroups behavior change) | Немає даних |

---

## Зведена таблиця

| Критерій | **Crate** | **BastilleBSD** |
|---|---|---|
| Зрілість | Alpha (активна розробка) | Стабільний (v1.4.0, лютий 2026) |
| Модель jail-у | Ефемерний (+ COW persistent) | Персистентний |
| GUI/Робочий стіл | **Перевершує** (5 режимів X11, VNC, noVNC, GUI-менеджер, clipboard, D-Bus) | Не підтримує |
| Серверне керування | Мінімальне | **Перевершує** |
| Інтеграція з ZFS | **Повна** (snapshots, COW, шифрування, datasets) | **Повна** (+ send/recv, migrate, 7 форматів) |
| Безпека (глибина) | **Перевершує** (securelevel, cpuset, children.max, pathnames.h, env, MAC, Capsicum, DNS, execv) | Добрі типові налаштування (securelevel=2) |
| Мережеві режими | **4** (NAT, bridge, passthrough, netgraph) + DHCP, VLAN, static MAC, іменовані мережі | 5+ (VNET, bridge, passthrough, alias, inherit + netgraph) |
| IPv6 | **Так** (epair IPv6, ipfw ip6, pf inet6) | **Так** (dual-stack, SLAAC, rdr) |
| Розмір контейнера | **Оптимізований** (ELF-аналіз) | Повна система |
| Міграція | Ні | **Так** (export → scp → import; jail працює під час snapshot, даунтайм при switchover) |
| Шаблони | YAML-специфікація з успадкуванням | Bastillefile (Docker-подібний) |
| Кількість команд | 11 (+підкоманди snapshot, gui) | 39 |
| Linux jail-и | Ні | Так (Ubuntu Noble/Focal/Bionic, Debian) |
| Multi-OS | Ні | Так (FreeBSD, HardenedBSD, MidnightBSD, Linux) |
| Моніторинг | Ні | Так (monitor з auto-restart, cron-based) |
| Ресурсні обмеження (RCTL) | **Так** | **Так** |
| CPU pinning (cpuset) | **Так** | **Так** |
| DNS-фільтрація | **Так** | Ні |
| Clipboard/D-Bus/Socket | **Так** | Ні |
| Tor | Так | Через шаблони |
| API/Web UI | **Частково** (`crated` read-only API + Prometheus; `crate-hub` multi-host) | **Так** (bastille-api + bastille-ui) |
| JSON вивід | **Так** (`crate list -j`) | **Так** (`bastille list -j`) |
| Автоналаштування хоста | Ні | **Так** (`bastille setup`) |
| Екосистема | Приклади (Firefox, Kodi...) | Репозиторій шаблонів + bastille-ui |
| Готовність до FreeBSD 15.0+ | **Так** (JAIL_OWN_DESC, epair fix) | Немає даних |
| pkgbase (FreeBSD 16+) | **Так** | **Так** |

---

## Коли що використовувати?

### Crate краще підходить для:
- Запуску **десктопних GUI-застосунків** в ізольованому середовищі (Firefox, Chromium, Kodi)
- **Sandboxing** з глибокою ізоляцією (clipboard, D-Bus, DNS, MAC, Capsicum)
- **Одноразових** ізольованих середовищ виконання
- Мінімізації розміру контейнера (оптимізація ELF-залежностей)
- Сценаріїв, що потребують **X11/OpenGL/відео** з ізоляцією (5 режимів: shared, nested, headless, gpu, none)
- **Віддаленого доступу** до GUI через VNC/noVNC (браузерний доступ)
- Керування **множинними GUI-сесіями** (тайлінг, фокус, скріншоти)
- Застосунків з вимогами до **ZFS-шифрування** at-rest
- Per-container **DNS-фільтрації** (блокування ad/tracking доменів)
- Сценаріїв з високими вимогами до **безпеки** (securelevel, cpuset, CWE-426, CWE-59, MAC)
- **Інспекції та експорту** запущених контейнерів (`list`, `info`, `console`, `export`)

### BastilleBSD краще підходить для:
- **Серверної інфраструктури** та DevOps
- Керування **множиною** довгоживучих jail-ів (теги, пріоритети, залежності)
- **Міграції** jail-ів між серверами (включно з live)
- Автоматизації через **шаблони** (CI/CD)
- Гранулярного контролю **ресурсів** (CPU pinning, rctl)
- Сумісності з іншими менеджерами jail-ів (iocage, ezjail імпорт)
- Роботи з **Linux jail-ами** та кількома ОС
- Сценаріїв, що потребують **REST API** та програмного керування
- Мережевих режимів **alias та inherit** (недоступні в Crate)
- **Автоналаштування хоста** (`bastille setup`)
- **Моніторингу** з автоматичним перезапуском сервісів

---

## Що Crate міг би запозичити у BastilleBSD

1. ~~**Інтеграція з ZFS**~~ ✅ Реалізовано (snapshots, COW, шифрування, datasets)
2. ~~**Ресурсні обмеження**~~ ✅ Реалізовано (RCTL через `limits:` в YAML)
3. ~~**Перелік контейнерів**~~ ✅ Реалізовано (`crate list` з table/JSON виводом)
4. ~~**Експорт/Імпорт**~~ ✅ Реалізовано (`crate export/import` з SHA256, traversal-валідацією)
5. ~~**IPv6**~~ ✅ Реалізовано (epair IPv6, ipfw ip6, pf inet6)
6. ~~**CPU pinning**~~ ✅ Реалізовано (cpuset через `security:` в YAML)
7. **Персистентний режим** — можливість збереження jail між запусками (COW persistent — крок у цьому напрямку)
8. **Тонкі jail-и** — економія місця через спільну базову систему
9. ~~**Bridge/Passthrough/Netgraph**~~ ✅ Реалізовано (4 мережеві режими: NAT, bridge, passthrough, netgraph)
10. ~~**VLAN підтримка**~~ ✅ Реалізовано (802.1Q тегування, ID 1-4094)
11. ~~**Static MAC**~~ ✅ Реалізовано (детерміністичний SHA-256, vendor OUI `58:9c:fc`)
12. ~~**Кілька мережевих інтерфейсів**~~ ✅ Реалізовано (основний + додаткові через `extra[]`)
13. ~~**DHCP/SYNCDHCP**~~ ✅ Реалізовано (синхронне отримання lease для bridge/passthrough/netgraph)
14. **Live-міграція** — перенесення контейнера на інший хост (ZFS snapshot → export → scp → import через SSH; jail працює під час snapshot, але є даунтайм при stop/start switchover)
15. **Теги/мітки** — групування контейнерів за тегами
16. **Пакетні операції** — `ALL`, теги як TARGET, множинні цілі
17. **Пріоритети завантаження** — порядок старту/зупинки jail-ів
18. **Моніторинг з auto-restart** — watchdog сервісів з cron
19. **Автоналаштування хоста** — `setup`-подібна команда
20. ~~**REST API**~~ ✅ Частково реалізовано (`crated` з read-only API; write API заплановано)
21. **Копіювання файлів** — cp/jcp/rcp для runtime file transfer

## Що BastilleBSD міг би запозичити у Crate

1. **pathnames.h** — абсолютні шляхи до команд (захист від CWE-426)
2. **Очищення environment** — захист від LD_PRELOAD/PATH injection
3. **execv замість execvp** — виключення пошуку по PATH у setuid-контексті
4. **DNS-фільтрація** — per-jail блокування небажаних доменів
5. **GUI/Desktop ізоляція** — nested X11, контроль буфера обміну, ізоляція D-Bus
6. **MAC bsdextended** — гранулярні правила доступу через ugidfw
7. **Capsicum** — capability-based security для додаткової ізоляції
8. **COW файлова система** — прозорий COW для ефемерних операцій
9. **ZFS шифрування** — підтримка шифрованих datasets з коробки
10. **Archive traversal validation** — перевірка `..` перед розпакуванням
11. **JAIL_OWN_DESC** — race-free jail removal через owning descriptor
12. **ELF-оптимізація** — агресивне зменшення розміру контейнера
13. **Signal-safe RAII cleanup** — гарантоване очищення при SIGINT/SIGTERM
14. **Автоматична IPv6 конфігурація** — повністю автоматичне налаштування IPv6 epair
