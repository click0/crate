# Анализ jailrun (hyphatech) vs crate (yurivict) — различия и план внедрения

## 1. Общая характеристика проектов

| Параметр | crate (yurivict) | jailrun (hyphatech) |
|----------|------------------|---------------------|
| Язык | C++17 | Python 3.13+ |
| Лицензия | BSD-3-Clause | BSD-3-Clause |
| Создан | Июнь 2019 | Март 2026 |
| Целевая ОС | FreeBSD нативно | macOS, Linux (через QEMU VM) |
| Формат конфигурации | YAML | UCL (libucl-совместимый) |
| Управление jail | Прямые вызовы jail(8)/jexec | Bastille (через SSH в VM) |
| Провизионирование | pkg install + scripts hooks | Ansible playbooks |
| Процесс-супервизор | rc.d (managed services) | monit |
| Файловая система | ZFS нативно | ZFS внутри VM + 9p shares |
| Сеть | ipfw NAT / if_bridge / pf anchors | pf внутри VM |
| GUI/Desktop | 5 X11 режимов, VNC, noVNC, GPU | Нет (серверные workloads) |

## 2. Архитектурные различия

### 2.1 Модель выполнения

**crate**: работает нативно на FreeBSD. Бинарник setuid root (`04755`) напрямую создаёт jail, настраивает сеть, монтирует FS. Всё в одном процессе.

**jailrun**: запускает полноценную FreeBSD VM через QEMU (с HVF/KVM ускорением), затем управляет jail внутри VM через SSH + Ansible. Многослойная архитектура:
```
Host (macOS/Linux) → QEMU VM (FreeBSD) → Bastille → jail
```

### 2.2 Конфигурация

**crate**: YAML-спецификация (.yml / .crate файлы). Поддержка template inheritance (`--template`). Системная конфигурация в `/usr/local/etc/crate.yml`.

**jailrun**: UCL формат (нативный для FreeBSD). Собственный UCL-парсер на Python (Lark LALR). Поддержка:
- Вложенных блочных комментариев `/* */`
- Heredoc `<<TAG ... TAG`
- Переменных `$VAR`, `${VAR}`
- Макросов `.include`, `.priority`
- Bare keys (автоматическое `= true`)
- SI-суффиксов (`10k`, `4G`, `30s`)

### 2.3 Управление зависимостями между jail

**crate**: Есть `depends` в `Spec`, но оркестрация стеков (`lib/stack.cpp`) — начальная стадия. Нет топологической сортировки на уровне CLI.

**jailrun**: Полноценный dependency graph:
- `depends ["postgres", "redis"]` в конфигурации
- `base { type = "jail"; name = "..." }` — клонирование из другого jail
- `TopologicalSorter` (stdlib Python) для определения порядка деплоя
- Автоматическое разрешение транзитивных зависимостей (`resolve_jail_dependencies`)
- Обнаружение циклов (`CycleError`)

### 2.4 Провизионирование

**crate**: lifecycle hooks (`run:begin`, `run:after-create-jail` и др.) + `pkg install`. Shell-скрипты в YAML-спеке.

**jailrun**: Ansible playbooks — полноценная система провизионирования:
- Локальные playbooks (`file = "setup.yml"`)
- Удалённые playbooks (`url = "https://github.com/.../playbook.yml"`)
- Кеширование удалённых playbooks с SHA256-верификацией (manifest-based)
- Переменные playbook (`vars { APP_ENV = "production"; }`)
- Hub репозиторий (`jailrun-hub`) с готовыми playbooks

### 2.5 Процесс-супервизор и Healthchecks

**crate**: `Healthcheck` struct в `spec.h` (test, interval, timeout, retries, startPeriod). Managed services через rc.d.

**jailrun**: monit-based supervision с healthchecks:
- `exec` блок с `cmd`, `dir`, `env`
- `healthcheck { test, interval, timeout, retries }`
- Jinja2 шаблоны для monitrc (`exec.monitrc.j2`, `monitrc.j2`)
- Автоматический перезапуск при сбое

### 2.6 Сетевая модель

**crate** (богаче):
- 4 режима: NAT, bridge, passthrough, netgraph
- IPv6: NAT ULA, SLAAC, static
- Static MAC (SHA-256, OUI `58:9c:fc`)
- VLAN 802.1Q
- Multiple interfaces per container
- Named networks в системном конфиге
- pf anchors per container
- DNS filtering (unbound)
- Dynamic firewall slots

**jailrun** (проще):
- Одна виртуальная сеть 10.17.89.0/24 внутри VM
- Port forwarding host → VM → jail через QEMU usermode networking + pf rdr
- Автоматическое назначение IP через fping sweep
- Inter-jail DNS через /etc/hosts (playbook `jail-hosts.yml`)

### 2.7 Testing framework

**crate**: `tests/ci-verify.sh` — минимальный CI скрипт.

**jailrun**: Полноценный testing framework для интеграции с pytest:
- `jailrun.testing.commons.Jail` — базовый класс с context manager
- `PostgresJail`, `RedisJail`, `MySQLJail`, `MariaDBJail`, `InfluxJail`
- Retry-логика для ожидания готовности сервиса (tenacity)
- Автоматический `__enter__` (create DB) / `__exit__` (drop DB)
- Пример: `with PostgresJail(Path("config.ucl"), jail="pg") as pg: ...`

### 2.8 State management

**crate**: Нет persistent state. Каждый запуск `crate run` — автономный. `crate list` использует `jls` для обнаружения запущенных jail.

**jailrun**: Полноценный state file (`~/.jrun/state.json`):
- Pydantic models для сериализации (State, JailState, BaseState)
- Сравнение old_state vs new_state для определения необходимости перезапуска VM
- Derive plan (Plan) с описанием изменений: создание, удаление, stale mounts
- Atomic save через tmp + rename

### 2.9 CLI

**crate**: 11 команд, ручной парсинг аргументов (`cli/args.cpp`).

**jailrun**: 8 команд через Typer (Python CLI framework):
- `start`, `stop`, `ssh`, `up`, `down`, `pause`, `status`, `purge`
- Rich-based отрисовка таблиц и деревьев
- File lock (`exclusive()` decorator) для предотвращения параллельного запуска
- Автоматическое определение версии из pyproject.toml

### 2.10 Кроссплатформенность

**crate**: Только FreeBSD (нативно, `libjail`).

**jailrun**: macOS (Apple Silicon + Intel) и Linux (x86_64 + aarch64):
- Автоматическое определение arch (aarch64 vs amd64)
- HVF на macOS, KVM на Linux
- Cloud-init для начальной настройки VM
- Homebrew tap для macOS установки

## 3. Полезные идеи из jailrun для внедрения в crate

### 3.1 ВЫСОКИЙ ПРИОРИТЕТ

#### A. UCL-конфигурация как альтернатива/дополнение к YAML
UCL — нативный формат FreeBSD (pkg.conf, jail.conf). Jailrun написал полноценный UCL-парсер (885 строк, `ucl.py`). Для crate:
- Добавить поддержку `.ucl` файлов наряду с `.yml`
- Использовать libucl (C-библиотека, уже есть в base FreeBSD) вместо собственного парсера
- Позволит нативную интеграцию с FreeBSD экосистемой

#### B. Dependency graph и стек-оркестрация
Jailrun реализует полную систему зависимостей:
- Топологическая сортировка
- Транзитивное разрешение зависимостей
- Обнаружение циклов
- Деплой в правильном порядке

Для crate: довести `lib/stack.cpp` до полноценной реализации, добавить `crate up stack.yml` аналогично `jrun up stack.ucl`.

#### C. Declarative state management
Модель "desired state → derive plan → apply changes":
- Хранить текущее состояние контейнеров
- При `crate up` сравнивать текущее с желаемым
- Применять только diff (не пересоздавать всё)
- Атомарное сохранение state

#### D. Ansible/provisioning интеграция
Ansible playbooks — мощнее shell-хуков:
- Идемпотентность
- Готовые модули для pkg, service, file, template
- Hub/registry готовых playbooks
- Переменные для параметризации

Для crate: добавить опциональный `setup` блок в YAML-спеку, поддерживающий Ansible playbooks. Shell-хуки оставить для простых случаев.

#### E. Testing framework
Pytest-фикстуры для интеграционного тестирования с реальными сервисами:
- `CrateJail` базовый класс
- `PostgresCrate`, `RedisCrate` и т.д.
- Автоматический подъём/снос jail
- Проверка готовности сервиса с retry

### 3.2 СРЕДНИЙ ПРИОРИТЕТ

#### F. Remote playbooks с manifest-based кешированием
Система загрузки и верификации удалённых playbooks:
- GitHub blob URL → raw URL конверсия
- SHA256-manifest для целостности
- Локальный кеш с проверкой хешей
- Поддержка pinning к тегу/ревизии

Для crate: реализовать `crate pull` для загрузки рецептов из реестра.

#### G. Inter-container DNS (jail discovery by name)
Jailrun генерирует `/etc/hosts` внутри каждого jail с именами всех соседних jail. Простая, но эффективная реализация (playbook `jail-hosts.yml`).

Для crate: добавить аналогичную генерацию `/etc/hosts` при запуске контейнеров в одной сети.

#### H. Monit-based process supervision
Monit вместо rc.d для supervision:
- Healthchecks с HTTP/TCP/script проверками
- Автоматический перезапуск при сбое
- Настраиваемые интервалы и таймауты
- Среды переменных для процессов (`env {}`)

#### I. Rich CLI вывод
Status в виде таблиц и деревьев (Rich library):
- Цветной вывод
- Отображение стека: VM → Jails → Processes
- Индикация managed/unmanaged/stale jail

Для crate: `crate list` и `crate info` улучшить Rich-подобным выводом.

#### J. File lock (exclusive execution)
Jailrun использует `exclusive()` декоратор для предотвращения параллельного запуска мутирующих команд. Crate не имеет защиты от одновременного запуска.

### 3.3 НИЗКИЙ ПРИОРИТЕТ (nice-to-have)

#### K. Cloud-init интеграция
Jailrun использует cloud-init для начальной настройки VM. Для crate нет прямого применения (нативный FreeBSD), но идея полезна для remote deployment: создание контейнеров на удалённых серверах.

#### L. Pydantic-like config validation
Jailrun использует Pydantic для строгой типизации конфигурации. В C++ аналог: добавить строгую валидацию с понятными сообщениями об ошибках (сейчас `validate.cpp` частично это делает).

#### M. Автоматическое назначение IP из пула
Jailrun сканирует сеть (`fping -u`) для поиска свободных IP. Для crate: IP pool в named networks с `ip: auto`.

## 4. Что есть в crate, чего нет в jailrun

Эти возможности crate уникальны и представляют конкурентное преимущество:

1. **GUI/Desktop** — 5 режимов X11, VNC, noVNC, GPU passthrough, clipboard isolation, D-Bus
2. **Продвинутая сеть** — 4 режима, VLAN, multiple interfaces, named networks, pf anchors
3. **Безопасность** — securelevel, RCTL, MAC bsdextended/portacl, Capsicum, pathnames.h
4. **ZFS интеграция** — snapshots, encryption, COW (ephemeral/persistent), clone
5. **Export/Import** — `.crate` архивы с SHA256, OS version checking
6. **Daemon (crated)** — REST API, Prometheus metrics
7. **SNMP** — crate-snmpd для мониторинга
8. **Hub** — multi-host управление контейнерами
9. **Нативная производительность** — C++, прямые syscall, без VM overhead
10. **DNS filtering** — per-jail unbound с domain blocking

## 5. План внедрения (порядок работ)

### Фаза 1: Foundation (state + dependencies)
1. Реализовать persistent state для запущенных контейнеров
2. Довести dependency graph (топологическая сортировка, цикл-детектор)
3. Добавить `crate up` команду для стек-деплоя
4. Добавить file lock для мутирующих операций

### Фаза 2: Provisioning
5. Добавить Ansible integration как опциональный `setup` блок
6. Реализовать remote recipe fetching с manifest + cache
7. Inter-container DNS (/etc/hosts генерация)

### Фаза 3: Supervision + Healthchecks
8. Интегрировать monit (или аналог) для process supervision
9. Полноценные healthchecks с retry и restart policy

### Фаза 4: UX
10. Улучшить CLI вывод (`crate list`, `crate status`, `crate info`)
11. Добавить `crate stop TARGET`, `crate restart TARGET`
12. UCL-конфигурация как альтернатива YAML

### Фаза 5: Testing
13. Testing framework (pytest-фикстуры для интеграционных тестов)
14. Unit тесты для spec/config parsing
