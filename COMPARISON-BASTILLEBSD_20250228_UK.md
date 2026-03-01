# Crate vs BastilleBSD — Детальне порівняння

> Оновлена версія (2025). Попередня версія: [COMPARISON-BASTILLEBSD-v1-pre-2025.md](COMPARISON-BASTILLEBSD-v1-pre-2025.md).

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
- 4 команди: `create`, `run`, `validate`, `snapshot`
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
- ~40 підкоманд для повного керування життєвим циклом
- Jail-и зберігаються на диску (ZFS або UFS)
- Підтримка тонких (thin) та товстих (thick) jail-ів

---

## CLI-команди

### Crate (4 команди)
| Команда | Опис |
|---|---|
| `crate create -s spec.yml -o app.crate` | Створити контейнер зі специфікації |
| `crate create -s spec.yml --template base.yml` | Створити з успадкуванням від шаблону |
| `crate create -s spec.yml --use-pkgbase` | Створити через pkgbase (FreeBSD 16+) |
| `crate run -f app.crate [-- args]` | Запустити контейнер |
| `crate validate -s spec.yml` | Перевірити специфікацію |
| `crate snapshot create\|list\|restore\|delete\|diff` | Керування ZFS-знімками |

### BastilleBSD (~40 підкоманд)
| Команда | Опис |
|---|---|
| `bastille bootstrap` | Завантажити реліз FreeBSD/Linux або шаблон |
| `bastille create` | Створити jail (thin/thick/clone/empty/linux) |
| `bastille start/stop/restart` | Керування запуском |
| `bastille destroy` | Видалити jail або реліз |
| `bastille console` | Увійти до jail (інтерактивна сесія) |
| `bastille cmd` | Виконати команду в jail-і |
| `bastille clone` | Клонувати jail |
| `bastille rename` | Перейменувати jail |
| `bastille migrate` | Мігрувати jail на віддалений сервер (live для ZFS) |
| `bastille export/import` | Експорт/імпорт jail-ів (сумісний з iocage, ezjail) |
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
| `bastille monitor` | Watchdog сервісів з auto-restart (з v1.0) |
| `bastille cp/jcp/rcp` | Копіювання файлів (host↔jail, jail↔jail) |
| `bastille convert` | Конвертація thin↔thick |
| `bastille etcupdate` | Оновлення /etc |
| `bastille verify` | Перевірка релізу |
| `bastille setup` | Автоналаштування (loopback, bridge, vnet, netgraph, firewall, storage) |
| `bastille edit` | Редагування конфігурації jail-у |
| `bastille sysrc` | Безпечне редагування rc-файлів |

**Висновок**: BastilleBSD надає значно ширший набір команд для керування повним життєвим циклом jail-ів. Crate зосереджується на 4 ключових операціях: збирання, запуск, перевірка та керування знімками.

---

## Типи jail-ів

| Тип | **Crate** | **BastilleBSD** |
|---|---|---|
| Тонкі (thin/shared base) | Ні — кожен .crate повністю самодостатній | **Так** (типово) — спільна базова система через nullfs |
| Товсті (thick/independent) | Фактично так — кожен .crate містить повну копію | **Так** (прапорець `-T`) |
| Клони (clone) | **Так** (ZFS COW clone під час запуску) | **Так** (прапорець `-C`, ZFS clone) |
| Порожні (empty) | Ні | **Так** (прапорець `-E`) — для власних збірок |
| Linux jail-и | Ні | **Так** (`-L`, Ubuntu Noble/Focal/Bionic, Debian; без VNET) |

---

## Зберігання даних та ZFS

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **Нативна інтеграція з ZFS** | **Так** | **Так** (підкоманда `zfs`) |
| **ZFS snapshots** | **Так** (`crate snapshot create/list/restore/delete/diff`) | **Так** |
| **ZFS clone (COW)** | **Так** (автоматичний при `cow/backend: zfs`) | **Так** (для тонких jail-ів) |
| **ZFS шифрування** | **Так** (`encrypted: true` в spec, перевірка під час запуску) | Ні (шифрування на рівні пулу) |
| **ZFS datasets в jail** | **Так** (`zfs-datasets:` в YAML, `allow.mount.zfs`) | **Так** (`bastille zfs jail`, v1.0+) |
| **ZFS send/recv** | Ні | **Так** (live експорт без зупинки jail, migrate) |
| **Copy-on-Write (COW)** | **Так** (ZFS clone або unionfs, ephemeral/persistent режими) | Через ZFS clone |
| **UFS** | Так (типово) | **Так** |
| **Shared dirs** | Так (nullfs в YAML) | Так (`bastille mount`) |
| **Shared files** | Так (hardlink + fallback mount) | Через mount |
| **Формат контейнера** | `.crate` (XZ-архів) | Каталог на файловій системі |
| **Оптимізація розміру** | **Так** (ELF-аналіз, видалення зайвого) | Ні (повна система) |
| **ZFS опції при створенні** | Ні | Так (`-Z "compression=lz4,atime=off"`, v0.14+) |
| **pkgbase (FreeBSD 16+)** | **Так** (прапорець `--use-pkgbase`) | **Так** (`bootstrap --pkgbase`) |

**Висновок**: Crate тепер має повноцінну інтеграцію з ZFS, включно зі знімками, COW-клонами, шифруванням та підключенням datasets до jail. BastilleBSD як і раніше лідирує за ZFS send/recv для міграції.

---

## Мережа

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **VNET** | Так (epair, автоматичне налаштування) | Так (5 режимів: -V, -B, -P, alias, inherit) |
| **Фізичний інтерфейс** | Ні | Так (`-V` — автостворення bridge + epair) |
| **Bridge** | Ні | Так (`-B` — підключення до наявного мосту) |
| **Passthrough** | Ні | Так (`-P` — прямий проброс інтерфейсу, v1.1+) |
| **Netgraph** | Ні | Так (`bastille setup netgraph`, альтернатива if_bridge, v1.0+) |
| **NAT** | Так (ipfw NAT, автоматичні правила) | Через pf loopback NAT (`bastille rdr`) |
| **Перенаправлення портів** | Так (inbound-tcp/udp в YAML) | Так (`bastille rdr`, +IPv6 у v1.4) |
| **IP-адресація** | Автоматична (10.0.0.0/8, до ~8M контейнерів) | Ручна або DHCP (SYNCDHCP для VNET) |
| **DNS** | **Опціональна пересилка + DNS-фільтрація** | Через `bastille edit resolv.conf` |
| **Контроль вихідного трафіку** | **Так** (wan/lan/host/dns гранулярність) | Через правила файрволу (pf/ipfw) |
| **VLAN** | Ні | Так (`--vlan ID`, v0.14+) |
| **Static MAC** | Ні | Так (прапорець `-M`) |
| **IPv6** | Ні | **Так** (dual-stack `-D`, SLAAC, IPv6 rdr у v1.4) |
| **Динамічні epair** | Ні (статичні) | Так (`e0a_jailname`/`e0b_jailname`, v1.0+) |
| **Кілька інтерфейсів** | Ні | Так (`bastille network add/remove`, v0.14+) |
| **Checksum offload workaround** | **Так** (FreeBSD 15.0 epair bug) | Немає даних |

**Висновок**: Crate забезпечує зручне автоматичне керування мережею з гранулярним контролем вихідного трафіку та DNS-фільтрацією. BastilleBSD пропонує значно більше мережевих режимів (5 типів + netgraph), IPv6, DHCP, VLAN та конфігурації корпоративного рівня.

---

## Файрвол

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **ipfw** | **Так** (автоматичні NAT правила) | Так (ручне налаштування) |
| **pf** | **Так** (per-container pf anchor, §3) | **Так** (нативна інтеграція) |
| **Per-container policy** | **Так** (секція `firewall:` в YAML: block_ip, allow_tcp/udp, default_policy) | Через правила pf |
| **Динамічні слоти** | **Так** (FwSlots: унікальні номери правил, без конфліктів, §18) | pf rdr-anchor з таблицями |
| **Перенаправлення портів** | В YAML: `inbound-tcp: {3100: 3000}` | `bastille rdr TARGET tcp 80 8080` |
| **Автоочищення правил** | **Так** (RAII, ref-counting для спільних правил) | `bastille rdr TARGET list/clear` |
| **ip.forwarding** | Автозбереження/відновлення початкового значення | Ручне налаштування |

**Висновок**: Crate тепер підтримує обидва файрволи (ipfw та pf), з per-container firewall policy через pf anchors та автоматичним керуванням ipfw через динамічні слоти. BastilleBSD орієнтований на pf з повним контролем якорів та таблиць.

---

## Графіка та робочий стіл

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **X11 (shared)** | **Так** (проброс X11-сокета + Xauthority) | Ні (не цільовий сценарій) |
| **X11 (nested/Xephyr)** | **Так** (ізольований вкладений X-сервер, §11) | Ні |
| **X11 (disabled)** | **Так** (`mode: none`) | — |
| **Ізоляція буфера обміну** | **Так** (режими: isolated/shared/none, напрямок: in/out/both, §12) | Ні |
| **Ізоляція D-Bus** | **Так** (контроль system/session bus, allow_own/deny_send, §13) | Ні |
| **OpenGL/GPU** | **Так** (апаратне прискорення) | Ні |
| **Відеопристрої** | **Так** (проброс /dev/videoN) | Ні |
| **GUI-застосунки** | **Так** (Firefox, Chromium, Kodi тощо) | Ні (серверна орієнтація) |

**Висновок**: Crate унікально позиціонований для запуску десктопних GUI-застосунків у jail-ах з повною ізоляцією: вкладений X11, фільтрація буфера обміну, контроль D-Bus. BastilleBSD орієнтований виключно на серверні навантаження.

---

## Безпека

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **securelevel** | Не задається | **securelevel = 2** типово |
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
| **children.max** | Не задається | 0 (заборона вкладених jail) |
| **CPU pinning** | Ні | Так (cpuset) |
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

**Висновок**: Crate пропонує значно глибшу багаторівневу модель безпеки: MAC bsdextended/portacl, Capsicum, DNS-фільтрація, ізоляція буфера обміну та D-Bus, pathnames.h для CWE-426, очищення env, execv, lstat для symlink-атак, JAIL_OWN_DESC для race-free cleanup. BastilleBSD має добрі типові налаштування безпеки (securelevel=2) та ресурсні обмеження, але менше можливостей для тонкого контролю.

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
- Docker-подібний синтаксис з 17 хуками: ARG, ARG+, CMD, CONFIG, CP, INCLUDE, LIMITS, LINE_IN_FILE, MOUNT, PKG, RDR, RENDER, RESTART, SERVICE, SYSRC, TAGS
- Обов'язкові аргументи (`ARG+`, v1.4+) — переривання за відсутності
- Вбудовані змінні: `${JAIL_NAME}`, `${JAIL_IP}`, `${JAIL_IP6}`
- Шаблони в Git-репозиторіях з підтримкою підкаталогів (v1.0+)
- Застосовуються до вже створених jail-ів
- Застарілий багатофайловий формат видалено (з v1.2.2)

**Висновок**: Crate описує все в одному YAML-файлі з глибоким налаштуванням безпеки, мережі, ZFS, GUI, DNS та IPC. Підтримує успадкування шаблонів. BastilleBSD використовує Docker-подібний Bastillefile, більш звичний для DevOps-фахівців.

---

## Керування життєвим циклом

| Можливість | **Crate** | **BastilleBSD** |
|---|---|---|
| **Створення** | Так (create, +шаблони, +pkgbase) | Так (create, з безліччю опцій) |
| **Запуск** | Так (run, ефемерний) | Так (start) |
| **Зупинка** | Автоматична при виході (RAII) | Так (stop) |
| **Перезапуск** | Ні (перестворення) | Так (restart) |
| **ZFS snapshots** | **Так** (create/list/restore/delete/diff) | **Так** |
| **Клонування** | **Так** (COW під час запуску) | Так (clone) |
| **Перейменування** | Ні | Так (rename) |
| **Міграція** | Ні | **Так** (migrate, включно з live через ZFS) |
| **Оновлення ОС** | Перезбирання .crate | Так (update, upgrade, etcupdate) |
| **Експорт/Імпорт** | .crate файли | Так (сумісність з iocage/ezjail) |
| **Перелік** | Ні (ефемерна модель) | Так (list, з пріоритетним сортуванням) |
| **Моніторинг** | Ні | **Так** (top, htop, monitor з auto-restart, v1.0+) |
| **Валідація** | **Так** (`crate validate`) | Немає даних |
| **Теги** | Ні | Так (tags) |
| **Конвертація** | Ні | Так (thin↔thick, convert) |
| **Виявлення невідповідності версій** | **Так** (host vs container FreeBSD version) | Ні |

**Висновок**: BastilleBSD надає повний цикл керування jail-ами, включно з live-міграцією. Crate використовує ефемерну модель зі ZFS-знімками та COW-клонами. Crate додає команди validate та snapshot.

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
| **JSON вивід** | Ні | Так (`bastille list -j`) |

---

## Сумісність з OCI/Docker

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **OCI образи** | Ні | **Ні** |
| **Docker Hub** | Ні | Ні |
| **Dockerfile/Containerfile** | Ні | Ні (Bastillefile — власна система) |
| **Формат експорту** | `.crate` (XZ) | `.txz` / ZFS snapshot |

Обидві системи працюють виключно в екосистемі FreeBSD jail. Для OCI-контейнерів на FreeBSD рекомендується **Podman + ocijail**.

---

## API та вебінтерфейс

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **REST API** | Ні | **Так** (bastille-api, JSON payloads, з v1.0) |
| **Вебінтерфейс** | Ні | **Так** (bastille-ui — Go + HTML, з ttyd-терміналом) |
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
| GUI/Робочий стіл | **Перевершує** (nested X11, clipboard, D-Bus) | Не підтримує |
| Серверне керування | Мінімальне | **Перевершує** |
| Інтеграція з ZFS | **Повна** (snapshots, COW, шифрування, datasets) | **Повна** (+ send/recv, migrate) |
| Безпека (глибина) | **Перевершує** (pathnames.h, env, MAC, Capsicum, DNS, execv) | Добрі типові налаштування (securelevel=2) |
| Мережеві режими | 1 (epair+NAT) + pf anchors | 5+ (VNET, bridge, passthrough, alias, inherit + netgraph) |
| Розмір контейнера | **Оптимізований** (ELF-аналіз) | Повна система |
| Міграція | Ні | **Так (включно з live)** |
| Шаблони | YAML-специфікація з успадкуванням | Bastillefile (Docker-подібний) |
| Кількість команд | 4 (+підкоманди snapshot) | ~40 |
| Linux jail-и | Ні | Так (Ubuntu Noble/Focal/Bionic, Debian, експериментально) |
| Моніторинг | Ні | Так (monitor з auto-restart) |
| Ресурсні обмеження (RCTL) | **Так** | **Так** |
| DNS-фільтрація | **Так** | Ні |
| Clipboard/D-Bus/Socket | **Так** | Ні |
| Tor | Так | Через шаблони |
| API/Web UI | Ні | **Так** (bastille-api + bastille-ui) |
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
- Сценаріїв, що потребують **X11/OpenGL/відео** з ізоляцією
- Застосунків з вимогами до **ZFS-шифрування** at-rest
- Per-container **DNS-фільтрації** (блокування ad/tracking доменів)
- Сценаріїв з високими вимогами до **безпеки** (CWE-426, CWE-59, MAC)

### BastilleBSD краще підходить для:
- **Серверної інфраструктури** та DevOps
- Керування **множиною** довгоживучих jail-ів
- **Міграції** jail-ів між серверами (включно з live)
- Автоматизації через **шаблони** (CI/CD)
- Гранулярного контролю **ресурсів** (CPU pinning через cpuset)
- Сумісності з іншими менеджерами jail-ів (iocage, ezjail імпорт)
- Роботи з **Linux jail-ами**
- Сценаріїв, що потребують **REST API** та програмного керування
- Множинних **мережевих режимів** (bridge, passthrough, VLAN, IPv6)

---

## Що Crate міг би запозичити у BastilleBSD

1. ~~**Інтеграція з ZFS**~~ ✅ Реалізовано (snapshots, COW, шифрування, datasets)
2. **Персистентний режим** — можливість збереження jail між запусками (COW persistent — крок у цьому напрямку)
3. **Перелік/моніторинг** — команда для перегляду запущених контейнерів
4. ~~**Ресурсні обмеження**~~ ✅ Реалізовано (RCTL через `limits:` в YAML)
5. **Клонування** — створення копій наявних .crate (експорт/імпорт)
6. **Тонкі jail-и** — економія місця через спільну базову систему
7. **IPv6** — підтримка IPv6 в мережевому стеку
8. **Bridge/Passthrough** — додаткові мережеві режими
9. **Команда list** — перегляд доступних .crate файлів та запущених контейнерів
10. **Live-міграція** — перенесення працюючого контейнера на інший хост
11. **REST API** — програмний інтерфейс для інтеграції
12. **CPU pinning** — прив'язка jail до конкретних ядер CPU

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
