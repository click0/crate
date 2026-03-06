# crate

Crate — контейнеризатор для FreeBSD. Пакує застосунки та сервіси в ізольовані самодостатні контейнери (файли `.crate`) і запускає їх у виділених FreeBSD jail з автоматичною мережею, файрволом та очищенням ресурсів.

Контейнери Crate містять все необхідне для запуску — потрібні лише виконуваний файл `crate` та ядро FreeBSD.

**Мова:** C++17 | **Ліцензія:** BSD 3-Clause | **Статус:** Alpha (активна розробка з 2019)

[English version](README.md) | [Порівняння з BastilleBSD](docs/research/COMPARISON-BASTILLEBSD_UK.md)

## Можливості

### Керування контейнерами
* **11 команд**: `create`, `run`, `validate`, `snapshot`, `list`, `info`, `console`, `clean`, `export`, `import`, `gui`
* **YAML-специфікація** з успадкуванням шаблонів (`--template`)
* **Інтеграція з ZFS**: знімки (create/list/restore/delete/diff), COW-клони, шифрування (AES-256-GCM/CCM, AES-128), підключення datasets
* **Copy-on-Write**: ефемерний або персистентний режим через ZFS clone або unionfs
* **Експорт/Імпорт**: запущені контейнери в `.crate` архіви з SHA256-валідацією, захистом від traversal, перевіркою версії ОС
* **Перелік контейнерів** у таблиці або JSON (`crate list -j`)
* **Інтерактивна консоль** (`crate console TARGET`)
* **pkgbase** для FreeBSD 16+ (`--use-pkgbase`)

### Графіка та робочий стіл
* **5 режимів X11**: shared (X11 хоста), nested (Xephyr), headless (Xvfb), GPU (DRM leasing з nvidia/amdgpu/intel), none
* **VNC**: x11vnc з паролем, автоматичний вибір порту
* **noVNC/WebSocket**: доступ через браузер за допомогою websockify
* **Менеджер GUI-сесій** (`crate gui`): list, focus, attach, url, tile, screenshot, resize
* **Ізоляція буфера обміну**: режими isolated/shared/none з контролем напрямку (in/out/both)
* **Ізоляція D-Bus**: per-container політика system/session bus (allow_own, deny_send)
* **OpenGL/GPU прискорення**: апаратний рендеринг з автовизначенням драйверів
* **Відеопристрої**: проброс V4L `/dev/videoN`

### Мережа
* **4 мережеві режими**: NAT (за замовчуванням), bridge (`if_bridge`), passthrough (прямий NIC), netgraph (`ng_bridge`)
* **NAT режим**: ipfw з автоматичною адресацією 10.0.0.0/8, контроль вихідного трафіку (wan/lan/host/dns), проброс портів (TCP/UDP)
* **Bridge режим**: контейнер на фізичній мережі через `if_bridge` з DHCP або статичним IP
* **Passthrough режим**: виділений фізичний NIC передається безпосередньо контейнеру через VNET
* **Netgraph режим**: `ng_bridge` + `eiface` як альтернатива `if_bridge`
* **DHCP**: синхронне отримання lease (`SYNCDHCP`-семантика)
* **Статичний IP**: CIDR-нотація (напр. `192.168.1.50/24`) з gateway
* **IPv6**: NAT ULA (fd00:cra7:e::/48), SLAAC для bridge/passthrough/netgraph, статичні IPv6-адреси
* **Статичний MAC**: детерміністична генерація MAC-адрес (SHA-256, vendor OUI `58:9c:fc`)
* **VLAN**: 802.1Q тегування (ID 1-4094) для bridge/passthrough/netgraph режимів
* **Декілька інтерфейсів**: основний + додаткові інтерфейси, кожен з незалежними mode/IP/VLAN
* **Іменовані мережі**: визначення мережевих профілів у системному конфігу, посилання за іменем у специфікаціях контейнерів
* **pf anchors**: per-container файрвол (block_ip, allow_tcp/udp, default_policy)
* **DNS-фільтрація**: per-jail unbound з блокуванням доменів (wildcard-патерни, nxdomain/redirect)
* **Динамічні слоти файрволу**: унікальні номери правил, без конфліктів, RAII-очищення

### Безпека
* **securelevel**: налаштовуваний (-1 auto / 0-3, default=2)
* **children.max**: налаштовуваний (default=0 — без вкладених jail)
* **CPU pinning**: cpuset через `security:` в YAML
* **RCTL ресурсні обмеження**: memoryuse, pcpu, maxproc, openfiles та 20+ інших ресурсів
* **MAC bsdextended**: ugidfw правила для гранулярного контролю доступу
* **MAC portacl**: обмеження прив'язки до портів
* **Capsicum**: sandbox на основі capabilities
* **pathnames.h**: абсолютні шляхи до всіх зовнішніх команд (захист від CWE-426)
* **Очищення environment**: чистий environ, відновлення лише TERM/DISPLAY/LANG
* **execv** (без пошуку по PATH) замість execvp у setuid-контексті
* **lstat** для перевірки symlink (захист від CWE-59)
* **JAIL_OWN_DESC**: race-free видалення jail (FreeBSD 15+)
* **Захист від directory traversal**: валідація шляхів перед розпакуванням
* **Signal-safe RAII cleanup**: гарантоване очищення ресурсів при SIGINT/SIGTERM
* **Ізоляція терміналу**: налаштовуваний devfs ruleset, TTY контроль

### Сервіси та IPC
* **Керовані сервіси**: авто-старт/стоп у порядку, генерація rc.conf
* **Socket proxying**: socat-проксі host<->jail сокетів
* **SysV IPC / POSIX mqueue**: налаштовуваний per container
* **Tor інтеграція**: вбудована опція tor проксі з опціональним control port

### Хуки життєвого циклу
* `run:begin`, `run:after-create-jail`, `run:before-start-services`, `run:before-execute`, `run:after-execute`, `run:end`
* `create:begin`, `create:end`

## Команди

| Команда | Опис |
|---|---|
| `crate create -s spec.yml -o app.crate` | Створити контейнер зі специфікації |
| `crate create -s spec.yml --template base.yml` | Створити з успадкуванням шаблону |
| `crate run -f app.crate [-- args]` | Запустити контейнер |
| `crate validate -s spec.yml` | Перевірити специфікацію |
| `crate snapshot create\|list\|restore\|delete\|diff` | Керування ZFS-знімками |
| `crate list [-j]` | Перелік запущених контейнерів (таблиця або JSON) |
| `crate info TARGET` | Детальна інформація про контейнер |
| `crate console TARGET [-u USER]` | Інтерактивна оболонка в контейнері |
| `crate clean [-n]` | Очищення ресурсів (підтримує dry-run) |
| `crate export TARGET [-o FILE]` | Експорт запущеного контейнера в .crate |
| `crate import FILE [-o FILE] [--force]` | Імпорт .crate з валідацією |
| `crate gui list\|focus\|attach\|url\|tile\|screenshot\|resize` | Менеджер GUI-сесій |

## Швидкий старт

```sh
# Створити контейнер зі специфікації
crate create -s examples/firefox.yml -o firefox.crate

# Запустити
crate run -f firefox.crate

# Переглянути запущені контейнери
crate list

# Відкрити оболонку в запущеному контейнері
crate console firefox

# Експортувати запущений контейнер
crate export firefox -o backup.crate
```

### Headless GUI з доступом через браузер

```yaml
# spec.yml
pkg:
    install: [firefox]
run:
    command: /usr/local/bin/firefox
options: [net]
gui:
    mode: headless
    vnc: true
    novnc: true
    vnc_password: secret
```

```sh
crate create -s spec.yml -o firefox-headless.crate
crate run -f firefox-headless.crate &
crate gui url firefox    # виведе noVNC URL для доступу через браузер
```

### Мережеві режими

```yaml
# NAT (за замовчуванням) — автоматичний IP, ipfw NAT, контроль вихідного трафіку
options:
    net:
        outbound: [wan, dns]
        inbound-tcp:
            8080: 80

# Bridge — контейнер на фізичній мережі через if_bridge
options:
    net:
        mode: bridge
        bridge: bridge0
        ip: dhcp
        static-mac: true

# Bridge зі статичним IP та VLAN
options:
    net:
        mode: bridge
        bridge: bridge0
        ip: 192.168.1.100/24
        gateway: 192.168.1.1
        vlan: 100
        ip6: slaac

# Passthrough — виділений NIC безпосередньо контейнеру
options:
    net:
        mode: passthrough
        interface: vtnet1
        ip: dhcp
        ip6: slaac

# Netgraph — альтернатива if_bridge через ng_bridge
options:
    net:
        mode: netgraph
        interface: em0
        ip: 192.168.1.100/24
        gateway: 192.168.1.1
        static-mac: true

# Декілька інтерфейсів
options:
    net:
        mode: bridge
        bridge: bridge0
        ip: dhcp
        extra:
            - mode: bridge
              bridge: bridge1
              ip: 10.0.0.50/24
              gateway: 10.0.0.1
              vlan: 100

# Використання іменованих мереж (визначених у crate.yml)
options:
    net:
        network: external
        ip: 192.168.1.50/24
        extra:
            - network: internal
              ip: 10.0.0.50/24
```

## Конфігурація

Файли конфігурації (YAML, вищий пріоритет перемагає):

| Файл | Область |
|---|---|
| `/usr/local/etc/crate.yml` | Системна |
| `/usr/local/etc/crate.d/*.yml` | Drop-in фрагменти (за алфавітом) |
| `~/.config/crate/crate.yml` | Користувацька |

Основні параметри: `prefix`, `cache`, `logs`, `zfs_enable`, `zfs_zpool`, `network_interface`, `default_bridge`, `static_mac_default`, `bootstrap_method`, `securelevel`, `children_max`, `search_path`, `compress_xz_options`, `networks`.

### Іменовані мережі

Визначення багаторазових мережевих профілів у системному конфігу з посиланням за іменем у специфікаціях контейнерів:

```yaml
# /usr/local/etc/crate.yml
networks:
    external:
        mode: bridge
        bridge: bridge0
        gateway: 192.168.1.1
        static-mac: true
    internal:
        mode: bridge
        bridge: bridge1
        gateway: 10.0.0.1
        vlan: 100
    dmz:
        mode: netgraph
        interface: em1
        gateway: 172.16.0.1
```

```yaml
# специфікація контейнера (.crate)
options:
    net:
        network: external
        ip: 192.168.1.50/24
        extra:
            - network: internal
              ip: 10.0.0.50/24
```

Поля іменованої мережі працюють як значення за замовчуванням — явно вказані значення у специфікації контейнера завжди мають пріоритет.

## Шаблони

Каталог `templates/` містить готові базові конфігурації:

| Шаблон | Опис |
|---|---|
| `standard.yml` | NAT з WAN+DNS, спільна тека Downloads |
| `development.yml` | NAT з повним доступом, спільна домашня тека, SysV IPC |
| `minimal.yml` | Мінімальний jail, без мережі, без X11 |
| `privacy.yml` | Tor проксі, ZFS шифрування, ефемерний COW, DNS-фільтрація |
| `network-isolated.yml` | Без мережі, nested X11 (1280x720) |
| `bridge-dhcp.yml` | Bridge режим з DHCP та статичним MAC |
| `bridge-static.yml` | Bridge режим зі статичним IP та gateway |
| `passthrough.yml` | Passthrough з DHCP та IPv6 SLAAC |
| `netgraph.yml` | Netgraph режим з DHCP та статичним MAC |

## Приклади

Каталог `examples/` містить готові специфікації:

**Десктопні застосунки:**
firefox, chromium, gimp, thunderbird, meld, mpv, vlc, qbittorrent, qtox, telegram-desktop, xfce-desktop

**Headless/GPU режими:**
firefox-headless, firefox-gpu, chromium-headless, chromium-gpu, gimp-headless, blender-gpu, glxgears-gpu

**Мережеві сервіси:**
gogs, nginx, syncthing, tor, i2pd

**Приватність (Tor/I2P):**
chromium+tor, firefox+i2pd, chromium+i2pd, qbittorrent+i2pd

**Утиліти:**
nmap, amass, wget, aria2, fetch, gzip, yt-dlp, xeyes

## Довідка YAML-специфікації

Підтримувані ключі верхнього рівня у файлах `.crate` / `.yml`:

| Ключ | Опис |
|---|---|
| `base` | `keep`, `keep-wildcard`, `remove` — керування файлами базової системи |
| `pkg` | `install`, `local-override`, `nuke` — керування пакунками |
| `run` | `command`, `service` — що запускати в контейнері |
| `dirs` | `share` — спільні теки (host<->jail) |
| `files` | `share` — спільні файли (host<->jail) |
| `options` | `net`, `x11`, `ssl-certs`, `tor`, `video`, `gl`, `no-rm-static-libs`, `dbg-ktrace` |
| `scripts` | Хуки життєвого циклу (run:begin, run:after-create-jail тощо) |
| `security` | `securelevel`, `children_max`, `cpuset`, `enforce_statfs`, `allow_*` |
| `limits` | RCTL ресурсні обмеження (memoryuse, pcpu, maxproc тощо) |
| `ipc` | `sysvipc`, `mqueue`, `raw_sockets` |
| `zfs` | `datasets` — додаткові ZFS datasets |
| `encrypted` | ZFS шифрування (method, keyformat, cipher) |
| `cow` | Copy-on-Write (mode: ephemeral/persistent, backend: zfs/unionfs) |
| `dns_filter` | DNS-фільтрація (allow, block, redirect_blocked) |
| `firewall` | Per-container pf політика (block_ip, allow_tcp/udp, default) |
| `x11` | X11 дисплей (mode: nested/shared/none, resolution, clipboard) |
| `gui` | GUI сесія (mode: nested/headless/gpu/auto, vnc, novnc, resolution) |
| `clipboard` | Ізоляція буфера обміну (mode: isolated/shared/none, direction) |
| `dbus` | D-Bus політика (system, session, policy/allow_own/deny_send) |
| `services` | Керовані сервіси (managed list, auto_start) |
| `socket_proxy` | Проксі сокетів (share, proxy з host/jail/direction) |
| `terminal` | Ізоляція терміналу (devfs_ruleset, allow_raw_tty) |
| `security_advanced` | Capsicum, MAC bsdextended/portacl, hide_other_jails |

## Встановлення

Через порти FreeBSD:
```sh
cd /usr/ports/sysutils/crate && make install clean
```

Або збірка з вихідних кодів:
```sh
make && sudo make install
```

**Залежності:** yaml-cpp, libjail

### Додаткові компоненти

```sh
make install-daemon       # crated — демон керування контейнерами
make install-examples     # приклади специфікацій до /usr/local/share/examples/crate
make install-completions  # автодоповнення shell
```

## Сумісність

**Підтримується:** FreeBSD 13.0 та новіші (13.x, 14.x, 15.x). Усі версійно-специфічні функції мають безпечні fallback-шляхи.

Адаптації для FreeBSD 15.0 (автоматичні, без дій з боку користувача):
* JAIL_OWN_DESC — race-free видалення jail через owning descriptor (на старших ядрах використовує `jail_remove()`)
* Виправлення checksum offload для epair — `txcsum`/`txcsum6` вимикаються безумовно (безпечно на 13.x/14.x)
* Попередження про невідповідність версій ОС — виявляє різницю major-версій FreeBSD між хостом та контейнером
* Попередження про сумісність ipfw — сповіщає коли хост FreeBSD 15 запускає контейнер зі старішою базою

## Застереження

* Вхідні мережеві порти не можуть бути доступні з хоста, на якому запущений контейнер, через [цю помилку](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=239590), наразі до них можна підключитися лише з інших хостів.

## Статус проєкту

`crate` знаходиться на стадії альфа. Активна розробка з червня 2019.

## Список завдань

Дивіться файл TODO у проєкті.
