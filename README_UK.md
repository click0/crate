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
| `crate run NAME [-- args]` | Запустити профіль за іменем: специфікація з `~/.config/crate/profiles/`, `/usr/local/share/crate/profiles/` або встановлених прикладів, `.crate` збирається при першому запуску (1.1.59) |
| `crate profile-from-trace -o spec.yml -- CMD [args]` | Один раз запустити CMD на хості під `truss(1)` і скласти чернетку мінімальної специфікації з того, чого програма торкалась (1.1.60) |
| `crate validate -s spec.yml` | Перевірити специфікацію |
| `crate snapshot create\|list\|restore\|delete\|diff` | Керування ZFS-знімками |
| `crate list [-j]` | Перелік запущених контейнерів (таблиця або JSON) |
| `crate info TARGET` | Детальна інформація про контейнер |
| `crate console TARGET [-u USER]` | Інтерактивна оболонка в контейнері |
| `crate clean [-n]` | Очищення ресурсів (підтримує dry-run) |
| `crate export TARGET [-o FILE] [-P PASSFILE] [-K SIGNKEY]` | Експорт запущеного контейнера в .crate (опціональне шифрування + ed25519-підпис) |
| `crate import FILE [-o FILE] [--force] [-P PASSFILE] [-V PUBKEY]` | Імпорт .crate з валідацією (авто-розшифрування, перевірка підпису) |
| `crate gui list\|focus\|attach\|url\|tile\|screenshot\|resize` | Менеджер GUI-сесій |
| `crate top` | Інтерактивний моніторинг ресурсів у стилі htop по всіх запущених контейнерах (1 Гц; `q` — вихід) |

## Швидкий старт

```sh
# Створити контейнер зі специфікації
crate create -s examples/firefox.yml -o firefox.crate

# Запустити
crate run -f firefox.crate

# ...або без обох кроків: встановлені приклади — це профілі (1.1.59)
crate run firefox

# Переглянути запущені контейнери
crate list

# Відкрити оболонку в запущеному контейнері
crate console firefox

# Експортувати запущений контейнер
crate export firefox -o backup.crate
```

### Шифрований експорт/імпорт

`.crate` артефакти переносні — на відміну від jail'ів Bastille, що
прив'язані до місця — і починаючи з 0.5.4 можуть бути **приватними**.
Експорт обгортається у `AES-256-CBC + PBKDF2` через `openssl enc(1)`,
тож той самий образ можна переносити між хостами без витоку файлової
системи стороннім, що мають доступ до мережі чи бекап-сховища.

```sh
# 1. Записати парольну фразу у файл (режим 0600 — лише власник)
printf 'cRatE2026craTE#UKR' > /etc/crate/secret
chmod 0600 /etc/crate/secret

# 2. Експорт із шифруванням
crate export firefox -P /etc/crate/secret -o firefox.crate
# -> firefox.crate         (шифротекст AES-256-CBC)
# -> firefox.crate.sha256  (рахується по шифротексту)

# 3. scp/rsync на цільовий хост …

# 4. Імпорт — шифрування авто-визначається за magic-байтами
crate import firefox.crate -P /etc/crate/secret
# Без -P на шифрованому архіві імпорт швидко падає з зрозумілим повідомленням.
```

Зауваги:
- Парольна фраза `cRatE2026craTE#UKR` — лише приклад, оберіть свою. PBKDF2
  робить brute force дорогим, але сильна фраза — все ще ваша відповідальність.
- Файл із паролем передається через `-kfile <path>` у `openssl`, тож секрет
  ніколи не з'являється у командному рядку і не видно через `ps`.
- `crate` відмовиться працювати з паролем-файлом, що не має `0600`, не
  є regular file або порожній.
- `.sha256` sidecar покриває **шифротекст**: якщо хочете детектувати
  bit-flip під час перенесення — звіряйте його out-of-band перед
  розшифровкою.
- Для автентифікації походження ("цей архів справді від мене"),
  поєднуйте `-P` з `-K`/`-V` (ed25519-підпис — див. нижче).

### Підписаний експорт/імпорт (ed25519)

Шифрування (флаг `-P` вище) дає **конфіденційність**. Підпис дає
**автентичність** — отримувач може переконатися, що `.crate` справді
прийшов від володаря відповідного секретного ключа, навіть якщо
проходив через недовірених посередників. Ці два механізми незалежні
і можуть комбінуватися.

```sh
# 1. Один раз: згенерувати пару ключів ed25519
openssl genpkey -algorithm ED25519 -out crate-sign.key
openssl pkey -in crate-sign.key -pubout -out crate-sign.pub
chmod 0600 crate-sign.key
# (crate-sign.pub можна публікувати будь-де; crate-sign.key тримати в секреті)

# 2. Підписати при експорті. Комбінується з -P для конфіденційності + автентичності.
crate export firefox -K crate-sign.key -P /etc/crate/secret -o firefox.crate
# -> firefox.crate         (шифротекст AES-256-CBC)
# -> firefox.crate.sha256  (по шифротексту)
# -> firefox.crate.sig     (підпис ed25519 по шифротексту)

# 3. На стороні отримувача: перевірити публічним ключем.
crate import firefox.crate -V crate-sign.pub -P /etc/crate/secret
# Відмовляється імпортувати, якщо firefox.crate.sig відсутній/не збігається —
# якщо тільки не передано --force.
```

Що саме підписується: **байти архіву на диску** (разом із шифрованим
шаром). Тому:
- Спотворений шифротекст виявляється підписом ще до того, як
  отримувач введе парольну фразу.
- Публічний ключ може перевірити походження не маючи парольної фрази.
- Непідписаний архів імпортується нормально; *підписаний* архів
  без `-V` відмовляється імпортуватися (свідомо — opt-in у
  слабший непідписаний режим через `--force`).

Зауваги:
- Реалізація: `openssl pkeyutl -sign -rawin -inkey ed25519-key`.
  ed25519 видає фіксований 64-байтовий підпис; `.sig` — бінарний файл.
- Файл секретного ключа відхиляється, якщо mode не `0600`, не
  regular або порожній.
- Шлях до підпису: `<archive>.sig`. Якщо verifier exit-код ≠ 0,
  імпорт переривається, якщо тільки не передано `--force`.

### Журнал аудиту

Кожна state-changing команда crate (`create`, `run`, `stop`,
`restart`, `snapshot`, `export`, `import`, `clean`, `console`, `gui`,
`stack`) дописує один рядок JSON у `/var/log/crate/audit.log`. Команди
лише для читання (`list`, `info`, `stats`, `logs`, `validate`)
пропускаються — щоб журнал лишався компактним.

```sh
$ crate create -s spec.yml -o myapp.crate
...
$ tail -1 /var/log/crate/audit.log | jq .
{
  "ts":      "2026-05-01T20:55:01Z",
  "pid":     12345,
  "uid":     1000,                          // реальний uid (користувач)
  "euid":    0,                             // ефективний uid (setuid root)
  "gid":     1000,
  "egid":    0,
  "user":    "alice",
  "host":    "build-server",
  "cmd":     "create",
  "target":  "spec.yml",
  "argv":    "'crate' 'create' '-s' 'spec.yml' '-o' 'myapp.crate'",
  "outcome": "ok"
}
```

Зауваги:
- Файл живе під `Config::Settings::logs` (за замовчуванням
  `/var/log/crate`); змінюється через `crate.yml`.
- Mode 0640, append-only — готовий до `auditd(8)` / `syslogd(8)`.
  Ротуйте через `newsyslog(8)`.
- Захоплюються **обидва** uid/gid (real + effective), щоб ревізор
  бачив "користувач X (uid=1000) діяв через euid=0" — важливо для
  setuid-бінарників.
- Спарювати записи `outcome: "started"` і `outcome: "ok"` за `pid`,
  щоб міряти тривалість команди; `failed: <msg>` містить текст
  винятку для post-mortem.

### Автоматичне створення bridge

Раніше bridge-режим вимагав, щоб оператор створив `bridge0` (або
інший інтерфейс зі spec) до `crate run`. Тепер spec може дати згоду
на створення на льоту:

```yaml
options:
    net:
        mode: bridge
        bridge: bridge0
        auto_create_bridge: true
        ip: dhcp
```

Якщо bridge уже існує, `auto_create_bridge` нічого не робить (тож
кілька контейнерів можуть ділити `bridge0` без гонок). Якщо bridge
відсутній і прапор виставлено, crate створює його (`ifconfig bridge0
create up`) і знищує при teardown лише якщо саме crate створив його у
цьому запуску. Без прапора відсутність bridge дає зрозумілу помилку,
що вказує на опцію.

Ім'я інтерфейсу перевіряється проти `[A-Za-z0-9_]{1,15}` з
обов'язковим driver-префіксом та обов'язковим unit-номером —
помилки на кшталт `brige0` ловляться до того, як дістануться
`ifconfig(8)`.

### Інтерактивний моніторинг ресурсів (`crate top`)

`crate top` опитує всі crate-керовані клітки раз на секунду і малює
таблицю з CPU%, пам'яттю, дисковим записом та кількістю процесів для
кожного контейнера. Натисніть `q` (або Ctrl-C) для виходу. CPU% може
перевищувати 100% на багатоядерних клітках — наприклад, рядок
build-ci нижче використовує близько трьох ядер:

```
NAME               JID              IP    CPU%        MEM       DISK  PROC
postgres            12      10.0.0.20    14.2    420.0 MB    12.5 MB    23
nginx-edge          15      10.0.0.21     3.1     48.0 MB     0 B        7
build-ci            18      10.0.0.22   210.5      1.2 GB    340.0 MB   42
3 jails  CPU 227.8%  MEM 1.7 GB  DISK 352.5 MB  PROC 72
```

Якщо stdout не є терміналом (`crate top | grep`, `watch crate top`),
рендер виводить один кадр і виходить. `crate top` — read-only команда
і не потрапляє у `/var/log/crate/audit.log`.

### Кросдискові спільні файли

`files:`-шейри більше не вимагають, щоб шлях на хості і шлях у клітці
лежали на одній файловій системі. Коли `crate run` бачить, що пара
шляхів перетинає межу пристрою (хост на tmpfs, датасет клітки на
іншому ZFS-пулі, зовнішній диск тощо), він автоматично переходить на
single-file `nullfs`-байнд-маунт замість жорсткого посилання, яке
повертає `EXDEV`. Семантика всередині клітки ідентична:
читання/запис, редагування на місці, власник і права відповідають
файлу на хості.

```yaml
# Це працює незалежно від того, чи /etc/resolv.conf і датасет
# клітки на одному пристрої. crate сам обирає для кожного файлу:
# жорстке посилання (один пристрій) або nullfs-байнд (різні).
files:
  /etc/resolv.conf: /etc/resolv.conf
  /var/log/myapp.log: /home/me/logs/myapp.log
```

Таблиця стратегій опублікована в `CHANGELOG.md` (0.6.0); чиста логіка
вибору міститься в `lib/share_pure.{h,cpp}` з 9 ATF-кейсами, які
покривають кожну клітинку матриці (host_exists × jail_exists ×
same_device).

### Безпека X11-режимів

`crate` підтримує п'ять режимів X11-дисплея — і **вони не рівнозначні
з погляду безпеки**. І `crate validate`, і `crate run` видають
попередження, коли обрано слабкий режим ізоляції.

| Режим | Ізоляція | Використовуйте коли |
|---|---|---|
| `nested` (Xephyr) | Сильна: контейнери отримують власний X-сервер | desktop-додатки, дефолт для production |
| `headless` (Xvfb) + VNC/noVNC | Сильна: жодного доступу до X-сервера хоста | server/автоматизація/скріншоти |
| `gpu` (DRM leasing) | Сильна: виділений GPU, без X-сервера хоста | додатки з апаратним прискоренням |
| `shared` | **Жодної** — повний read/write до X-сервера хоста | лише всередині повністю довірених jail'ів |
| `none` | — | без GUI |

**Чому `shared` небезпечний.** Монтування `/tmp/.X11-unix` хоста в jail
означає, що будь-який процес всередині цього jail може:
- Читати кожне натискання клавіші у будь-якому додатку на хості
  (X — глобальний, не per-window).
- Переміщати/піднімати/мінімізувати/закривати будь-яке вікно хоста.
- Знімати скріншоти всього робочого столу.

`crate` попереджає про це і при `crate validate spec.yml`, і при запуску.
Оператори, які свідомо приймають ризик, можуть вимкнути runtime-попередження
встановивши `CRATE_X11_SHARED_ACK=1`.

```yaml
# НІ (поведінка за замовчуванням для старих специфікацій)
options: [x11]               # ⚠️ неявний mode=shared

# ТАК
options: [x11]
x11:
    mode: nested             # приватний Xephyr-сервер для кожного jail
    resolution: 1920x1080
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

## Профілі

`crate run NAME` без `-f` (1.1.59, за зразком `<app>.profile` + `<app>.local` у firejail) шукає специфікацію за іменем, перший збіг виграє:

| Шлях | Хто пише |
|---|---|
| `~/.config/crate/profiles/NAME.yml` | оператор |
| `/usr/local/share/crate/profiles/NAME.yml` | сайт (каталог створює оператор, належить root) |
| `/usr/local/share/examples/crate/NAME.yml` | постачається з crate — приклади і є набором профілів |

`.crate` збирається при першому запуску в `~/.local/share/crate/profiles/NAME.crate` і далі використовується повторно; перезбирається, коли профіль або його `.local` новіші. Jail називається як профіль, точно як при `-f NAME.crate`. Збірка — це `crate create`, якому досі потрібен root: непривілейований оператор отримує повідомлення з точним рецептом `crate create -s … -o … && chown` для root (злита специфікація вже записана), а коли архів існує — запускає як звично.

Необов'язковий `~/.config/crate/profiles/NAME.local.yml` зливається поверх профілю: map — ключ за ключем, списки — доповнюються без дублікатів, `options` — за іменем опції, скаляри — замінюються. Він може додавати пакунки, опції, ліміти, аргументи запуску і спільні каталоги в межах `$HOME`:

```yaml
# ~/.config/crate/profiles/firefox.local.yml
pkg:
    install: [noto-emoji]
run:
    command: /usr/local/bin/firefox --private-window
dirs:
    share:
        - [$HOME/Downloads, $HOME/Downloads]
limits:
    memoryuse: 4G
```

Він **не може** послабити те, що обрав автор профілю: `security_advanced`, `dbus`, `base`, `scripts`, `encrypted`, `securelevel`, `socket_proxy` і спільні каталоги поза домашнім відхиляються з поясненням. Для такого скопіюйте профіль у `~/.config/crate/profiles/` і редагуйте копію. Злита специфікація записується поряд з архівом як `NAME.yml` (згенерований файл) і саме вона потрапляє у `+CRATE.SPEC`. Імена профілів підпорядковуються правилу імен jail (`[A-Za-z0-9._-]`), тож приклади на кшталт `chromium+tor` потребують копії з дефісом в імені.

З 1.1.59 `crate create --template` використовує те саме YAML-злиття, і злита специфікація потрапляє в архів; раніше шаблон впливав лише на збірку, і crate із `--template privacy` запускався без tor, шифрування, COW та DNS-фільтра.

## Чернетка специфікації з трейсу

`crate profile-from-trace -o app.yml -- <команда> [аргументи]` (1.1.60, за зразком `--build` у firejail) **один раз запускає програму на хості, без пісочниці**, під `truss -f` і перетворює трейс на чернетку мінімальної специфікації:

| Побачено в трейсі | Стає |
|---|---|
| виконані програми з `/usr/local` | `pkg/install` (власники через `pkg which`; пакунки, з яких лише читали, — коментар) |
| файли у домашньому каталозі | `dirs/share` / `files/share` з `$HOME`; каталоги стану на кшталт `.config/<app>`, `.local/share/<app>`, `.mozilla` окремим списком з коментарем «прибери, щоб лишити в контейнері»; `.cache`, `.Xauthority` і login-dotfiles пропускаються |
| інші каталоги | `dirs/share`, згорнуті до найкоротших предків; базова система, `/usr/local`, `/tmp`, `/var`, `/dev`, `/mnt`, `/media` ігноруються |
| сокети X11 / D-Bus, `/dev/dri`, `/dev/video*`, файли сертифікатів | `x11`, `dbus/session` або `dbus/system`, `gl`, `video`, `ssl-certs` |
| вихідні з'єднання | `options/net/outbound` за класом адреси (`wan`, `lan`, `host`, `dns` для порту 53); проста опція `net`, коли потрібні всі чотири |
| `bind`+`listen`, прив'язки datagram-сокетів | `inbound-tcp`, `inbound-udp` |

Побачені адреси, звукові/вхідні/USB-пристрої, сокети Wayland, невідомі unix-сокети й файли `/usr/local` без пакунка стають коментарями наприкінці. `--trace-file FILE` бере збережений вивід `truss` замість запуску; `--keep-trace FILE` зберігає сирий трейс. Перегляньте чернетку, потім `crate validate -s app.yml` і `crate create`.

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
firefox, chromium, gimp, thunderbird, meld, mpv, vlc, qbittorrent, qtox, telegram-desktop, xfce-desktop, lxqt-desktop, lxqt-desktop-nested, lxqt-minimal, lxqt-wayland

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

### Через порти FreeBSD

```sh
cd /usr/ports/sysutils/crate && make install clean
```

Порт підтримує OPTIONS збірки (увімкнені за замовчуванням, якщо не зазначено інше):

| Опція | Опис |
|---|---|
| `DAEMON` | Демон керування контейнерами (crated) |
| `SNMPD` | SNMP-агент моніторингу (crate-snmpd) |
| `EXAMPLES` | Приклади специфікацій контейнерів |
| `COMPLETIONS` | Автодоповнення Bash/ZSH (вимкнено за замовчуванням) |
| `ZFS` | Нативний ZFS API (libzfs) |
| `IFCONFIG` | Нативне налаштування інтерфейсів (libifconfig) |
| `PFCTL` | Нативне керування PF файрволом (libpfctl) |
| `CAPSICUM` | Підтримка Capsicum sandbox (libcasper) |
| `LIBVIRT` | Підтримка віртуальних машин (bhyve через libvirt) |
| `X11` | Проброс X11 дисплею |
| `VNCSERVER` | Вбудований VNC-сервер (libvncserver) (вимкнено за замовчуванням) |
| `LIBSEAT` | Керування DRM/GPU сесіями (libseat) |

```sh
# Інтерактивне налаштування опцій
cd /usr/ports/sysutils/crate && make config && make install clean
```

### З вихідних кодів

```sh
make && sudo make install
```

**Залежності:** yaml-cpp, libjail

**Прапорці збірки** (встановіть `=0` для вимкнення):

```sh
make HAVE_LIBZFS=1 HAVE_LIBIFCONFIG=1 HAVE_LIBPFCTL=1 HAVE_CAPSICUM=1 \
     WITH_LIBVIRT=1 WITH_X11=1 WITH_LIBSEAT=1 WITH_LIBVNCSERVER=0
```

Всі нативні API-обгортки мають fallback на shell-команди при збірці без відповідного прапорця.

### Make-цілі

| Ціль | Опис |
|---|---|
| `make` | Зібрати CLI `crate` |
| `make all-daemon` | Зібрати `crate` + демон `crated` |
| `make all-snmpd` | Зібрати `crate` + агент `crate-snmpd` |
| `make install` | Встановити crate CLI + man-сторінки |
| `make install-daemon` | Встановити crated, RC-скрипт, конфігурацію |
| `make install-snmpd` | Встановити crate-snmpd + MIB-файл |
| `make install-examples` | Встановити приклади до `/usr/local/share/examples/crate/` |
| `make install-completions` | Встановити автодоповнення shell |
| `make test` | Скомпілювати юніт-тести та запустити через kyua |

## crated — REST API демон

`crated` — демон керування життєвим циклом контейнерів з REST API для віддаленого керування.

### Можливості

* Слухає на **Unix-сокеті** (локально) та **TCP/TLS** (віддалено)
* **Автентифікація токенами** (SHA-256 хеші, ролі: `viewer`/`admin`)
* **Обмеження швидкості** (100 зап/с читання, 10 зап/с запис)
* **Prometheus-метрики** на `/metrics`
* Інтеграція з **RC-сервісами** FreeBSD

### API ендпоінти

| Ендпоінт | Авт. | Опис |
|---|---|---|
| `GET /healthz` | — | Перевірка стану |
| `GET /api/v1/containers` | — | Перелік запущених контейнерів |
| `GET /api/v1/containers/:name/gui` | — | Інформація GUI-сесії (дисплей, VNC/WS порти) |
| `GET /api/v1/containers/:name/stats` | так | Використання ресурсів (RCTL) |
| `GET /api/v1/containers/:name/logs` | так | Логи (`?follow=true`, `?tail=N`) |
| `POST /api/v1/containers/:name/start` | так | Запустити контейнер з .crate |
| `POST /api/v1/containers/:name/stop` | так | Зупинити контейнер (SIGTERM → SIGKILL) |
| `POST /api/v1/containers/:name/restart` | так | Зупинка + запуск одним викликом |
| `DELETE /api/v1/containers/:name` | так | Знищити контейнер |
| `GET /api/v1/containers/:name/snapshots` | так | Перелік ZFS-снапшотів |
| `POST /api/v1/containers/:name/snapshots` | так | Створити снапшот (тіло: `{"name":"<snap>"}` необов'язкове) |
| `DELETE /api/v1/containers/:name/snapshots/:snap` | так | Видалити снапшот |
| `GET /api/v1/containers/:name/stats/stream` | так | Server-Sent Events потік RCTL-лічильників (1 Гц) |
| `GET /api/v1/containers/:name/console` (WS) | так | RFC 6455 WebSocket — інтерактивна `/bin/sh` через PTY (окремий listener; роль admin) |
| `POST /api/v1/containers/:name/export` | так | Експорт активного контейнера в `/var/run/crate/<name>-<unixtime>.crate`; повертає `{file,size,sha256}` |
| `GET /api/v1/exports/:filename` | так | Стрім раніше експортованого `.crate` до клієнта |
| `POST /api/v1/imports/:name` | так | Завантаження raw `.crate` (octet-stream); атомарне rename у `/var/run/crate/<name>.crate` |
| `GET /api/v1/host` | — | Інформація про хост-систему |
| `GET /metrics` | — | Prometheus-метрики |

#### WebSocket-консоль

Інтерактивна консоль слухає окремий TCP-сокет (`console_ws.port`
у `crated.conf`; за замовчуванням 0 — вимкнено), не спільний з HTTP API.
Реалізує RFC 6455 версії 13. Handshake вимагає
`Authorization: Bearer <admin-token>`; далі daemon пропускає байти
між WebSocket-з'єднанням і `/bin/sh -i` всередині клітки, запущеною
через `jexec(8)`. Сервер→клієнт використовує binary-кадри, щоб
TTY-escape-послідовності проходили без змін; клієнт→сервер кадри
(text або binary) пишуться у stdin шелу. PING/PONG працюють, CLOSE
завершує шел через SIGTERM.

Адреса bind проходить через `getaddrinfo(3)`, тож приймається
`127.0.0.1`, `::1`, `::` (dual-stack) або hostname:

```yaml
console_ws:
    port: 9802
    bind: "::"      # dual-stack, або 127.0.0.1 / ::1 для loopback
```

#### Потік статистики SSE

`/stats/stream` шле один кадр `data:` за секунду з полями
`{name, jid, ip, ts, <RCTL-лічильники...>}`. Клієнти можуть споживати
його чистим JavaScript через `new EventSource(...)` або через
`curl --no-buffer`. Потік завершується сам подією `event: end`, коли
клітка зникає.

#### Снапшот-ендпоінти

Імена снапшотів перевіряються на стороні сервера за регулярним виразом
`[A-Za-z0-9._-]{1,64}` (значення `.` та `..` відхиляються).
`POST /snapshots` без тіла генерує авто-ім'я виду
`auto_2026-05-01_220000`. `DELETE /snapshots/:snap` не є ідемпотентним:
повторний виклик повертає 500 з помилкою ZFS, бо й сам `zfs destroy`
не ідемпотентний.

### Конфігурація

```yaml
# /usr/local/etc/crated.conf
listen:
    unix: /var/run/crate/crated.sock
    tcp_port: 9800
    tcp_bind: 0.0.0.0

tls:
    cert: /usr/local/etc/crate/tls/server.pem
    key: /usr/local/etc/crate/tls/server.key
    ca: /usr/local/etc/crate/tls/ca.pem
    require_client_cert: true

auth:
    tokens:
        - name: ansible
          token_hash: "sha256:..."
          role: admin
        - name: grafana
          token_hash: "sha256:..."
          role: viewer

log:
    file: /var/log/crated.log
    level: info
```

### RC-сервіс

```sh
# /etc/rc.conf
crated_enable="YES"

# Керування
service crated start
service crated stop
service crated status
```

## crate-snmpd — SNMP-агент моніторингу

`crate-snmpd` — AgentX-підагент, що надає метрики контейнерів через SNMP. Збирає дані з `jls`/`rctl` та реєструє `CRATE-MIB` (встановлюється до `/usr/local/share/snmp/mibs/`).

```sh
make all-snmpd && sudo make install-snmpd
```

## Тестування

Проєкт використовує **Kyua** та **ATF** (стандартний фреймворк тестування FreeBSD).

```sh
make test                     # Зібрати та запустити всі тести
cd tests && kyua test         # Запуск з каталогу tests
kyua test unit/               # Лише юніт-тести
kyua test functional/         # Лише функціональні тести
kyua report -v                # Детальний звіт
```

**Юніт-тести** (C++17, libatf-c++): парсинг специфікацій, мережеві опції, IPv6, життєвий цикл jail, обробка помилок.

**Функціональні тести** (shell-based ATF): CLI-команди (`help`, `version`, `validate`, `list`).

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
