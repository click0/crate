# crate

Crate — контейнеризатор для FreeBSD. Пакує застосунки та сервіси в ізольовані самодостатні контейнери (файли `.crate`) і запускає їх у виділених FreeBSD jail з автоматичною мережею, файрволом та очищенням ресурсів.

Контейнери Crate містять все необхідне для запуску — потрібні лише виконуваний файл `crate` та ядро FreeBSD.

**Мова:** C++17 | **Ліцензія:** BSD 3-Clause | **Статус:** Alpha (активна розробка з 2019)

[English version](README.md) | [Порівняння з BastilleBSD](COMPARISON-BASTILLEBSD_UK.md)

## Можливості

### Керування контейнерами
* **11 команд**: `create`, `run`, `validate`, `snapshot`, `list`, `info`, `console`, `clean`, `export`, `import`, `gui`
* **YAML-специфікація** з успадкуванням шаблонів (`--template`)
* **Інтеграція з ZFS**: знімки (create/list/restore/delete/diff), COW-клони, шифрування, підключення datasets
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
* **VNET**: автоматичне створення epair з IPv4 та IPv6
* **NAT**: ipfw з автоматичним керуванням правилами
* **IPv6**: повна підтримка (fd00:cra7:e::/48 ULA, ipfw ip6, pf inet6, маршрутизація)
* **Проброс портів**: вхідний TCP/UDP через YAML
* **pf anchors**: per-container файрвол (block_ip, allow_tcp/udp, default_policy)
* **Контроль вихідного трафіку**: гранулярний доступ — wan/lan/host/dns
* **DNS-фільтрація**: per-jail unbound з блокуванням доменів (wildcard-патерни, nxdomain/redirect)
* **Динамічні слоти файрволу**: унікальні номери правил, без конфліктів, RAII-очищення

### Безпека
* **securelevel**: налаштовуваний (-1 auto / 0–3, default=2)
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
* **Socket proxying**: socat-проксі host↔jail сокетів
* **SysV IPC / POSIX mqueue**: налаштовуваний per container
* **Tor інтеграція**: вбудована опція tor проксі

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

## Конфігурація

Файли конфігурації (YAML, вищий пріоритет перемагає):

| Файл | Область |
|---|---|
| `/usr/local/etc/crate.yml` | Системна |
| `/usr/local/etc/crate.d/*.yml` | Drop-in фрагменти (за алфавітом) |
| `~/.config/crate/crate.yml` | Користувацька |

Основні параметри: `prefix`, `cache`, `logs`, `zfs_enable`, `zfs_zpool`, `network_interface`, `securelevel`, `children_max`, `search_path`, `compress_xz_options`.

## Приклади

Каталог `examples/` містить готові специфікації:

**Десктопні застосунки:**
firefox, chromium, gimp, thunderbird, libreoffice, telegram-desktop, vlc, mpv, meld, qbittorrent, qtox, xfce-desktop

**Headless/GPU режими:**
firefox-headless, firefox-gpu, chromium-headless, chromium-gpu, gimp-headless, libreoffice-headless, blender-gpu, glxgears-gpu

**Мережеві сервіси:**
gogs, nginx, syncthing, tor, i2pd

**Приватність (Tor/I2P):**
chromium+tor, firefox+i2pd, chromium+i2pd, qbittorrent+i2pd

**Утиліти:**
nmap, amass, wget, aria2, fetch, gzip, xeyes

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

## Сумісність з FreeBSD 15.0+

* JAIL_OWN_DESC — race-free видалення jail через owning descriptor
* Виправлення checksum offload для epair (вимкнення txcsum/txcsum6)
* Попередження про невідповідність версій ОС (host ≠ container)
* Попередження про сумісність ipfw (видалений legacy compat code)
* Адаптація до зміни поведінки getgroups(2)

## Застереження

* Вхідні мережеві порти не можуть бути доступні з хоста, на якому запущений контейнер, через [цю помилку](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=239590), наразі до них можна підключитися лише з інших хостів.

## Статус проєкту

`crate` знаходиться на стадії альфа. Активна розробка з червня 2019.

## Список завдань

Дивіться файл TODO у проєкті.
