# Crate vs BastilleBSD — Детальное сравнение

> Обновлённая версия (2025). Предыдущая версия: [COMPARISON-BASTILLEBSD-v1-pre-2025.md](COMPARISON-BASTILLEBSD-v1-pre-2025.md).

## Общее описание

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **Назначение** | Контейнеризатор FreeBSD — упаковывает пакеты и сервисы в изолированные самодостаточные «крейты» | Система автоматизации развёртывания и управления контейнеризированными приложениями на FreeBSD |
| **Язык** | C++17 (~4 000 строк) | Shell-скрипты (POSIX sh) |
| **Лицензия** | ISC | BSD |
| **Статус** | Alpha (с 2019, активная разработка) | Стабильный (v1.3.x, активная разработка с 2018) |
| **Философия** | Минималистичные одноразовые контейнеры для приложений; упор на десктопные приложения и GUI с глубокой изоляцией | Полноценный менеджер jail-ов для серверов и инфраструктуры; DevOps-ориентированный |
| **Зависимости** | yaml-cpp, libjail, librang | Только базовая система FreeBSD (sh, jail, zfs, pkg) |

---

## Архитектура и модель работы

### Crate — «Упаковка и запуск»
```
spec.yml → [crate create] → myapp.crate (XZ-архив)
                                  ↓
                            [crate run]
                                  ↓
                    Временный jail + ZFS COW + сеть + firewall
                                  ↓
                          Выполнение приложения
                                  ↓
              RAII-очистка (jail, mount, firewall, epair, ZFS)
```
- **Эфемерная модель**: jail создаётся при запуске и уничтожается после завершения
- 4 команды: `create`, `run`, `validate`, `snapshot`
- Агрессивная оптимизация: анализ ELF-зависимостей через ldd, удаление ненужных файлов
- Контейнер — самодостаточный XZ-архив (`.crate`)
- RAII-паттерны (RunAtEnd) гарантируют очистку даже при ошибках и сигналах

### BastilleBSD — «Создание и управление»
```
bastille bootstrap 14.2-RELEASE → базовый релиз
bastille create myjail 14.2-RELEASE 10.0.0.1 → persistent jail
bastille start/stop/restart myjail → управление жизненным циклом
bastille template myjail user/template → автоматизация настройки
```
- **Персистентная модель**: jail-ы живут долго, управляются как сервисы
- 35+ подкоманд для полного управления жизненным циклом
- Jail-ы хранятся на диске (ZFS или UFS)
- Поддержка тонких (thin) и толстых (thick) jail-ов

---

## CLI-команды

### Crate (4 команды)
| Команда | Описание |
|---|---|
| `crate create -s spec.yml -o app.crate` | Создать контейнер из спецификации |
| `crate create -s spec.yml --template base.yml` | Создать с наследованием от шаблона |
| `crate create -s spec.yml --use-pkgbase` | Создать через pkgbase (FreeBSD 16+) |
| `crate run -f app.crate [-- args]` | Запустить контейнер |
| `crate validate -s spec.yml` | Проверить спецификацию |
| `crate snapshot create\|list\|restore\|delete\|diff` | Управление ZFS-снапшотами |

### BastilleBSD (35+ подкоманд)
| Команда | Описание |
|---|---|
| `bastille bootstrap` | Загрузить релиз FreeBSD или шаблон |
| `bastille create` | Создать jail (thin/thick/clone/empty/linux) |
| `bastille start/stop/restart` | Управление запуском |
| `bastille destroy` | Удалить jail или релиз |
| `bastille console` | Войти в jail (интерактивная сессия) |
| `bastille cmd` | Выполнить команду в jail-е |
| `bastille clone` | Клонировать jail |
| `bastille rename` | Переименовать jail |
| `bastille migrate` | Мигрировать jail на удалённый сервер |
| `bastille export/import` | Экспорт/импорт jail-ов (совместим с iocage, ezjail) |
| `bastille template` | Применить шаблон к jail-у |
| `bastille pkg` | Управление пакетами в jail-е |
| `bastille service` | Управление сервисами |
| `bastille mount/umount` | Монтирование томов |
| `bastille network` | Управление сетевыми интерфейсами |
| `bastille rdr` | Перенаправление портов (host → jail) |
| `bastille limits` | Ресурсные ограничения (rctl/cpuset) |
| `bastille list` | Список jail-ов, релизов, шаблонов |
| `bastille config` | Получить/установить свойства jail-а |
| `bastille update/upgrade` | Обновление jail-а |
| `bastille tags` | Метки для jail-ов |
| `bastille zfs` | Управление ZFS для jail-ов |
| `bastille top/htop` | Мониторинг процессов |
| `bastille cp/jcp/rcp` | Копирование файлов (host↔jail, jail↔jail) |
| `bastille convert` | Конвертация thin↔thick |
| `bastille etcupdate` | Обновление /etc |
| `bastille verify` | Проверка релиза |
| `bastille setup` | Автонастройка сети, файрвола, хранилища |
| `bastille edit` | Редактирование конфигурации jail-а |
| `bastille sysrc` | Безопасное редактирование rc-файлов |

**Вывод**: BastilleBSD предоставляет значительно более широкий набор команд для управления полным жизненным циклом jail-ов. Crate фокусируется на 4 ключевых операциях: сборка, запуск, проверка и управление снапшотами.

---

## Типы jail-ов

| Тип | **Crate** | **BastilleBSD** |
|---|---|---|
| Тонкие (thin/shared base) | Нет — каждый .crate полностью самодостаточен | **Да** (по умолчанию) — общая базовая система через nullfs |
| Толстые (thick/independent) | Фактически да — каждый .crate содержит полную копию | **Да** (`-T` флаг) |
| Клоны (clone) | **Да** (ZFS COW clone при запуске) | **Да** (`-C` флаг, ZFS clone) |
| Пустые (empty) | Нет | **Да** (`-E` флаг) — для кастомных сборок |
| Linux jail-ы | Нет | **Да** (`-L`, экспериментально, через debootstrap) |

---

## Хранение данных и ZFS

| Возможность | **Crate** | **BastilleBSD** |
|---|---|---|
| **ZFS нативная интеграция** | **Да** | **Да** (подкоманда `zfs`) |
| **ZFS snapshots** | **Да** (`crate snapshot create/list/restore/delete/diff`) | **Да** |
| **ZFS clone (COW)** | **Да** (автоматический при `cow/backend: zfs`) | **Да** (для тонких jail-ов) |
| **ZFS шифрование** | **Да** (`encrypted: true` в spec, проверка при запуске) | Нет (шифрование на уровне пула) |
| **ZFS datasets в jail** | **Да** (`zfs-datasets:` в YAML, `allow.mount.zfs`) | **Да** |
| **ZFS send/recv** | Нет | **Да** (используется в migrate) |
| **Copy-on-Write (COW)** | **Да** (ZFS clone или unionfs, ephemeral/persistent режимы) | Через ZFS clone |
| **UFS** | Да (по умолчанию) | **Да** |
| **Shared dirs** | Да (nullfs в YAML) | Да (`bastille mount`) |
| **Shared files** | Да (hardlink + fallback mount) | Через mount |
| **Формат контейнера** | `.crate` (XZ-архив) | Каталог на файловой системе |
| **Оптимизация размера** | **Да** (ELF-анализ, удаление лишнего) | Нет (полная система) |
| **ZFS опции при создании** | Нет | Да (`-Z` флаг) |
| **pkgbase (FreeBSD 16+)** | **Да** (`--use-pkgbase` флаг) | **Да** (`bootstrap --pkgbase`) |

**Вывод**: Crate теперь имеет полноценную интеграцию с ZFS, включая снапшоты, COW-клоны, шифрование и подключение datasets к jail. BastilleBSD по-прежнему лидирует по ZFS send/recv для миграции.

---

## Сеть

| Возможность | **Crate** | **BastilleBSD** |
|---|---|---|
| **VNET** | Да (epair, автоматическая настройка) | Да (3 режима: -V, -B, -P) |
| **Физический интерфейс** | Нет | Да (`-V` — привязка к физическому интерфейсу) |
| **Bridge** | Нет | Да (`-B` — подключение к существующему мосту) |
| **Passthrough** | Нет | Да (`-P` — проброс интерфейса в jail) |
| **NAT** | Да (ipfw NAT, автоматические правила) | Через pf/ipfw (ручная настройка или rdr) |
| **Перенаправление портов** | Да (inbound-tcp/udp в YAML) | Да (`bastille rdr`) |
| **IP-адресация** | Автоматическая (10.0.0.0/8, до ~8M контейнеров) | Ручная (указывается при создании) |
| **DNS** | **Опциональная пересылка + DNS-фильтрация** | Настройка через `-n` флаг |
| **Outbound-контроль** | **Да** (wan/lan/host/dns гранулярность) | Через firewall-правила (pf/ipfw) |
| **VLAN** | Нет | Да (`-v` флаг) |
| **Static MAC** | Нет | Да (`-M` флаг) |
| **IPv6** | Нет | Да (улучшено в v1.0+) |
| **Checksum offload workaround** | **Да** (FreeBSD 15.0 epair bug) | Нет данных |

**Вывод**: Crate предоставляет удобное автоматическое управление сетью с гранулярным контролем исходящего трафика и DNS-фильтрацией. BastilleBSD предлагает значительно больше сетевых режимов и конфигураций уровня предприятия.

---

## Файрвол

| Возможность | **Crate** | **BastilleBSD** |
|---|---|---|
| **ipfw** | **Да** (автоматические NAT правила) | Да (ручная настройка) |
| **pf** | **Да** (per-container pf anchor, §3) | **Да** (нативная интеграция) |
| **Per-container policy** | **Да** (`firewall:` секция в YAML: block_ip, allow_tcp/udp, default_policy) | Через pf rules |
| **Динамические слоты** | **Да** (FwSlots: уникальные номера правил, без конфликтов, §18) | pf rdr-anchor с таблицами |
| **Порт-форвардинг** | В YAML: `inbound-tcp: {3100: 3000}` | `bastille rdr TARGET tcp 80 8080` |
| **Автоочистка правил** | **Да** (RAII, ref-counting для общих правил) | `bastille rdr TARGET list/clear` |
| **ip.forwarding** | Автосохранение/восстановление оригинального значения | Ручная настройка |

**Вывод**: Crate теперь поддерживает оба файрвола (ipfw и pf), с per-container firewall policy через pf anchors и автоматическим управлением ipfw через динамические слоты. BastilleBSD ориентирован на pf с полным контролем якорей и таблиц.

---

## Графика и десктоп

| Возможность | **Crate** | **BastilleBSD** |
|---|---|---|
| **X11 (shared)** | **Да** (проброс X11-сокета + Xauthority) | Нет (не целевой сценарий) |
| **X11 (nested/Xephyr)** | **Да** (изолированный вложенный X-сервер, §11) | Нет |
| **X11 (disabled)** | **Да** (`mode: none`) | — |
| **Clipboard isolation** | **Да** (режимы: isolated/shared/none, направление: in/out/both, §12) | Нет |
| **D-Bus isolation** | **Да** (system/session bus контроль, allow_own/deny_send, §13) | Нет |
| **OpenGL/GPU** | **Да** (аппаратное ускорение) | Нет |
| **Видеоустройства** | **Да** (/dev/videoN проброс) | Нет |
| **GUI-приложения** | **Да** (Firefox, Chromium, Kodi и т.д.) | Нет (серверная ориентация) |

**Вывод**: Crate уникально позиционирован для запуска десктопных GUI-приложений в jail-ах с полной изоляцией: вложенный X11, clipboard фильтрация, D-Bus контроль. BastilleBSD ориентирован исключительно на серверные нагрузки.

---

## Безопасность

| Возможность | **Crate** | **BastilleBSD** |
|---|---|---|
| **securelevel** | Не задаётся | **securelevel = 2** по умолчанию |
| **enforce_statfs** | **Настраиваемый** (auto/0/1/2, авто-определение для ZFS) | **2** (фиксированный) |
| **devfs_ruleset** | **Настраиваемый** (§16, terminal isolation) | Ruleset 4 по умолчанию; 13 для VNET |
| **RCTL ресурсы** | **Да** (любые RCTL-ресурсы через `limits:` в YAML) | **Да** (через `bastille limits`) |
| **MAC bsdextended** | **Да** (ugidfw правила через `security:` в YAML, §8) | Нет |
| **MAC portacl** | **Да** (mac_portacl через `security:`, §8) | Нет |
| **Capsicum** | **Да** (опция в `security:`, §8) | Нет |
| **raw_sockets** | Настраиваемый (через ipc: раздел) | **Запрещены** по умолчанию |
| **SysV IPC** | Настраиваемый (`ipc: sysvipc: true`) | Нет данных |
| **allow.mlock** | Настраиваемый | Нет данных |
| **allow.chflags** | Настраиваемый | Нет данных |
| **allow.set_hostname** | Настраиваемый | Нет данных |
| **allow.quotas** | Настраиваемый | Нет данных |
| **children.max** | Не задаётся | 0 (запрет вложенных jail) |
| **CPU pinning** | Нет | Да (cpuset) |
| **pathnames.h** | **Да** (абсолютные пути ко всем командам, CWE-426, §pathnames) | Bare names (PATH-relative) |
| **Очищение env** | **Да** (environ=empty, восстановление только TERM/DISPLAY/LANG) | Нет |
| **execv vs execvp** | **Да** (execv — без поиска по PATH) | execvp/system (через shell) |
| **lstat для symlink** | **Да** (CWE-59 защита) | Нет данных |
| **Jail descriptor** | **Да** (JAIL_OWN_DESC для race-free removal, FreeBSD 15+) | Нет |
| **Archive traversal** | **Да** (проверка `..` в архивах перед распаковкой) | Нет данных |
| **Signal-safe cleanup** | **Да** (SIGINT/SIGTERM → RAII destructors) | Через shell trap |
| **setuid проверка** | Да (требует setuid, запрет запуска из jail) | Да (root) |
| **DNS-фильтрация** | **Да** (per-jail unbound, блокировка доменов, §4) | Нет |
| **Socket proxying** | **Да** (socat-based, share/proxy, §15) | Нет |
| **Terminal isolation** | **Да** (devfs ruleset, TTY контроль, §16) | Нет данных |
| **Directory traversal защита** | **Да** (Util::safePath проверка shared dirs) | Нет данных |

**Вывод**: Crate предлагает значительно более глубокую многоуровневую модель безопасности: MAC bsdextended/portacl, Capsicum, DNS-фильтрация, clipboard и D-Bus изоляция, pathnames.h для CWE-426, env sanitization, execv, lstat для symlink-атак, JAIL_OWN_DESC для race-free cleanup. BastilleBSD имеет хорошие дефолты безопасности (securelevel=2) и ресурсные лимиты, но меньше опций для fine-grained контроля.

---

## Шаблонизация и автоматизация

### Crate — YAML-спецификация с наследованием шаблонов

```yaml
# spec.yml (§10: шаблоны через --template)
pkg:
    install: [firefox, git]
run:
    command: /usr/local/bin/firefox
options: [net, x11, gl, video]

# ZFS шифрование (§1)
encrypted: true

# COW файловая система (§6)
cow:
    backend: zfs        # или unionfs
    mode: ephemeral     # или persistent

# Ресурсные лимиты (§5)
limits:
    memoryuse: 512M
    pcpu: 50
    maxproc: 100

# DNS-фильтрация (§4)
dns:
    block: ["*.ads.example.com", "tracker.example.net"]
    redirect_blocked: nxdomain

# Per-container firewall (§3)
firewall:
    block_ip: ["192.168.0.0/16"]
    allow_tcp: [80, 443]
    default_policy: block

# X11 изоляция (§11)
x11:
    mode: nested        # Xephyr
    resolution: 1920x1080

# Clipboard (§12)
clipboard:
    mode: isolated
    direction: out      # только из jail → host

# D-Bus (§13)
dbus:
    session_bus: true
    system_bus: false
    deny_send: ["org.freedesktop.secrets"]

# IPC контроль (§7)
ipc:
    sysvipc: false
    raw_sockets: false

# Socket proxying (§15)
sockets:
    share: ["/var/run/dbus/system_bus_socket"]
    proxy:
        - host: /tmp/.X11-unix/X0
          jail: /tmp/.X11-unix/X0

# Security advanced (§8)
security:
    capsicum: true
    mac_rules: ["subject uid 1001 object not uid 1001 mode rsx"]

# ZFS datasets
zfs-datasets: ["zpool/data/myapp"]

# Жизненные хуки
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

Наследование шаблонов (`--template`): шаблонная спецификация мержится с пользовательской через `mergeSpecs()`.

### BastilleBSD — Bastillefile

```
# Bastillefile
CMD echo "Hello"
PKG nginx
SYSRC nginx_enable=YES
SERVICE nginx start
TEMPLATE /usr/local/etc/nginx/nginx.conf
OVERLAY /usr/local/www
```
- Docker-подобный синтаксис
- Команды: CMD, PKG, SYSRC, SERVICE, TEMPLATE, OVERLAY, CP, RDR, MOUNT, CONFIG и др.
- Шаблоны хранятся в Git-репозиториях
- Применяются к уже созданным jail-ам
- Консолидированный репозиторий шаблонов на GitLab

**Вывод**: Crate описывает всё в одном YAML-файле с глубокой конфигурацией безопасности, сети, ZFS, GUI, DNS и IPC. Поддерживает наследование шаблонов. BastilleBSD использует Docker-подобный Bastillefile, более привычный для DevOps.

---

## Управление жизненным циклом

| Возможность | **Crate** | **BastilleBSD** |
|---|---|---|
| **Создание** | Да (create, +шаблоны, +pkgbase) | Да (create, с множеством опций) |
| **Запуск** | Да (run, эфемерный) | Да (start) |
| **Остановка** | Автоматическая при выходе (RAII) | Да (stop) |
| **Перезапуск** | Нет (пересоздание) | Да (restart) |
| **ZFS snapshots** | **Да** (create/list/restore/delete/diff) | **Да** |
| **Клонирование** | **Да** (COW при запуске) | Да (clone) |
| **Переименование** | Нет | Да (rename) |
| **Миграция** | Нет | **Да** (migrate, включая live через ZFS) |
| **Обновление ОС** | Пересборка .crate | Да (update, upgrade, etcupdate) |
| **Экспорт/Импорт** | .crate файлы | Да (совместимость с iocage/ezjail) |
| **Список** | Нет (эфемерная модель) | Да (list, с приоритетной сортировкой) |
| **Мониторинг** | Нет | Да (top, htop, monitor) |
| **Валидация** | **Да** (`crate validate`) | Нет данных |
| **Теги** | Нет | Да (tags) |
| **Конвертация** | Нет | Да (thin↔thick, convert) |
| **Version mismatch detect** | **Да** (host vs container FreeBSD version) | Нет |

**Вывод**: BastilleBSD предоставляет полный цикл управления jail-ами, включая live-миграцию. Crate использует эфемерную модель с ZFS-снапшотами и COW-клонами. Crate добавляет validate и snapshot команды.

---

## Пакеты и сервисы

| Возможность | **Crate** | **BastilleBSD** |
|---|---|---|
| **Установка пакетов** | Да (в YAML: pkg.install) | Да (`bastille pkg`) |
| **Локальные пакеты** | Да (pkg.add, pkg.override) | Через cp + pkg |
| **pkgbase** | **Да** (`--use-pkgbase`) | **Да** (`--pkgbase`) |
| **Управление сервисами** | **Да** (run.service + managed services §14) | Да (`bastille service`) |
| **Managed services** | **Да** (auto-start, auto-stop в обратном порядке, rc.conf генерация) | Через sysrc + service |
| **Множественные сервисы** | Да | Да |
| **sysrc** | Через managed services rc.conf | **Да** (`bastille sysrc`) |
| **Автоочистка пакетов** | **Да** (удаление неиспользуемых зависимостей) | Нет |
| **Оптимизация (strip)** | **Да** (ELF-анализ, удаление документации) | Нет |

---

## DNS-фильтрация (уникальная возможность Crate)

| Возможность | **Crate** | **BastilleBSD** |
|---|---|---|
| **Per-jail DNS resolver** | **Да** (unbound, §4) | Нет |
| **Блокировка доменов** | **Да** (wildcard-паттерны) | Нет |
| **Redirect blocked** | **Да** (nxdomain или конкретный IP) | Нет |
| **Upstream forwarding** | **Да** (автоматически из resolv.conf хоста) | — |

---

## IPC и изоляция процессов

| Возможность | **Crate** | **BastilleBSD** |
|---|---|---|
| **SysV IPC** | **Настраиваемый** (§7) | Нет данных |
| **POSIX mqueue** | **Настраиваемый** (§7) | Нет данных |
| **raw_sockets** | **Настраиваемый** (override через ipc:) | Запрещены по умолчанию |
| **Socket proxying** | **Да** (socat, share/proxy, §15) | Нет |
| **D-Bus isolation** | **Да** (session/system bus, policy, §13) | Нет |
| **Clipboard control** | **Да** (isolated/shared, direction, §12) | Нет |

---

## Батчевые операции и таргетинг

| Возможность | **Crate** | **BastilleBSD** |
|---|---|---|
| **Множественные цели** | Нет (один контейнер) | **Да** — `ALL`, теги, списки через пробел |
| **Теги** | Нет | Да (`bastille tags TARGET tag1 tag2`) |
| **Приоритеты загрузки** | Нет | Да (`-p` — порядок старта/остановки) |
| **Зависимости** | Нет | Да (beta: зависимый jail автостартует) |
| **JSON вывод** | Нет | Да (`bastille list -j`) |

---

## OCI/Docker совместимость

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **OCI образы** | Нет | **Нет** |
| **Docker Hub** | Нет | Нет |
| **Dockerfile/Containerfile** | Нет | Нет (Bastillefile — своя система) |
| **Формат экспорта** | `.crate` (XZ) | `.txz` / ZFS snapshot |

Обе системы работают исключительно в экосистеме FreeBSD jail. Для OCI-контейнеров на FreeBSD рекомендуется **Podman + ocijail**.

---

## API и веб-интерфейс

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **API** | Нет | **Да** (bastille-api — базовый REST API) |
| **Веб-интерфейс** | Нет | Нет (CLI-only, API как foundation) |
| **Companion-инструменты** | Нет | **Rocinante** — применяет Bastillefile к хосту |

---

## Совместимость с FreeBSD 15.0+

| Возможность | **Crate** | **BastilleBSD** |
|---|---|---|
| **JAIL_OWN_DESC** | **Да** (race-free jail removal через owning descriptor) | Нет данных |
| **epair checksum fix** | **Да** (disable txcsum/txcsum6 workaround) | Нет данных |
| **Version mismatch warning** | **Да** (предупреждение при host ≠ container FreeBSD version) | Нет данных |
| **ipfw compat warning** | **Да** (FreeBSD 15.0 removed old ipfw compat code) | Нет данных |
| **getgroups(2) change** | **Да** (adjusted for setgroups behavior change) | Нет данных |

---

## Сводная таблица

| Критерий | **Crate** | **BastilleBSD** |
|---|---|---|
| Зрелость | Alpha (активная разработка) | Стабильный (v1.3+) |
| Модель jail-а | Эфемерный (+ COW persistent) | Персистентный |
| GUI/Десктоп | **Превосходит** (nested X11, clipboard, D-Bus) | Не поддерживает |
| Серверное управление | Минимальное | **Превосходит** |
| ZFS интеграция | **Полная** (snapshots, COW, шифрование, datasets) | **Полная** (+ send/recv, migrate) |
| Безопасность (глубина) | **Превосходит** (pathnames.h, env, MAC, Capsicum, DNS, execv) | Хорошие дефолты (securelevel=2) |
| Сетевые режимы | 1 (epair+NAT) + pf anchors | 4+ (VNET, bridge, passthrough, shared IP) |
| Размер контейнера | **Оптимизирован** (ELF-анализ) | Полная система |
| Миграция | Нет | **Да (включая live)** |
| Шаблоны | YAML-спецификация с наследованием | Bastillefile (Docker-подобный) |
| Количество команд | 4 (+подкоманды snapshot) | 35+ |
| Linux jail-ы | Нет | Да (экспериментально) |
| Мониторинг | Нет | Да |
| Ресурсные лимиты (RCTL) | **Да** | **Да** |
| DNS-фильтрация | **Да** | Нет |
| Clipboard/D-Bus/Socket | **Да** | Нет |
| Tor | Да | Через шаблоны |
| Экосистема | Примеры (Firefox, Kodi...) | Репозиторий шаблонов на GitLab |
| FreeBSD 15.0+ ready | **Да** (JAIL_OWN_DESC, epair fix) | Нет данных |
| pkgbase (FreeBSD 16+) | **Да** | **Да** |

---

## Когда использовать что?

### Crate лучше подходит для:
- Запуска **десктопных GUI-приложений** в изолированной среде (Firefox, Chromium, Kodi)
- **Sandboxing** с глубокой изоляцией (clipboard, D-Bus, DNS, MAC, Capsicum)
- **Одноразовых** изолированных сред выполнения
- Минимизации размера контейнера (оптимизация ELF-зависимостей)
- Сценариев, требующих **X11/OpenGL/видео** с изоляцией
- Приложений с требованиями к **ZFS-шифрованию** at-rest
- Per-container **DNS-фильтрации** (блокировка ad/tracking доменов)
- Сценариев с высокими требованиями к **безопасности** (CWE-426, CWE-59, MAC)

### BastilleBSD лучше подходит для:
- **Серверной инфраструктуры** и DevOps
- Управления **множеством** долгоживущих jail-ов
- **Миграции** jail-ов между серверами (включая live)
- Автоматизации через **шаблоны** (CI/CD)
- Гранулярного контроля **ресурсов** (CPU pinning через cpuset)
- Совместимости с другими менеджерами jail-ов (iocage, ezjail импорт)
- Работы с **Linux jail-ами**
- Сценариев, требующих **REST API** и программного управления
- Множественных **сетевых режимов** (bridge, passthrough, VLAN, IPv6)

---

## Что Crate мог бы позаимствовать у BastilleBSD

1. ~~**ZFS интеграция**~~ ✅ Реализовано (snapshots, COW, шифрование, datasets)
2. **Персистентный режим** — опция сохранения jail-а между запусками (COW persistent — шаг в этом направлении)
3. **Список/мониторинг** — команда для просмотра запущенных контейнеров
4. ~~**Ресурсные лимиты**~~ ✅ Реализовано (RCTL через `limits:` в YAML)
5. **Клонирование** — создание копий существующих .crate (экспорт/импорт)
6. **Тонкие jail-ы** — экономия места через общую базовую систему
7. **IPv6** — поддержка IPv6 в сетевом стеке
8. **Bridge/Passthrough** — дополнительные сетевые режимы
9. **Команда list** — просмотр доступных .crate файлов и запущенных контейнеров
10. **Live-миграция** — перенос работающего контейнера на другой хост
11. **REST API** — программный интерфейс для интеграции
12. **CPU pinning** — привязка jail к конкретным CPU ядрам

## Что BastilleBSD мог бы позаимствовать у Crate

1. **pathnames.h** — абсолютные пути к командам (CWE-426 protection)
2. **Очищение environment** — защита от LD_PRELOAD/PATH injection
3. **execv вместо execvp** — исключение PATH search для setuid-контекста
4. **DNS-фильтрация** — per-jail blocking нежелательных доменов
5. **GUI/Desktop изоляция** — nested X11, clipboard control, D-Bus isolation
6. **MAC bsdextended** — гранулярные правила доступа через ugidfw
7. **Capsicum** — capability-based security для дополнительной изоляции
8. **COW filesystem** — прозрачный COW для ephemeral операций
9. **ZFS encryption** — поддержка шифрованных datasets из коробки
10. **Archive traversal validation** — проверка `..` перед распаковкой
11. **JAIL_OWN_DESC** — race-free jail removal через owning descriptor
12. **ELF-оптимизация** — агрессивное уменьшение размера контейнера
