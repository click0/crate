# Список покращень для click0/crate

Складений на основі аналізу вихідного коду, TODO/FIXME коментарів, стабів, порівняння з BastilleBSD та сучасними контейнерними інструментами.

---

## 1. Критичні баги та зламаний код

### 1.1 `pkg/add` викликає `abort()` (lib/spec.cpp:655-656)
```cpp
std::cerr << "pkg/add tag is currently broken" << std::endl;
abort();
```
**Що робити:** або реалізувати `pkg/add` (встановлення .pkg файлів з локального шляху), або прибрати зі специфікації і видати нормальну помилку.

### 1.2 SNMP AgentX — повністю stub (snmpd/mib.cpp)
`initAgentX()`, `registerOids()`, `sendNotify()`, `shutdownAgentX()` — всі мають тіло `// TODO` і повертають stub. `initAgentX()` повертає `true` але нічого не робить.

### 1.3 Hub web dashboard — порожня директорія (hub/web/)
`hub/web/` існує але порожня. `crate-hub` серверить `srv.set_mount_point("/", webDir)` — але файлів немає.

---

## 2. Демон `crated` — F2 API не реалізований (daemon/routes.cpp:124-130)

Реалізовано (F1, read-only):
- `GET /api/v1/containers` — список контейнерів
- `GET /api/v1/containers/:name/gui` — інформація про GUI-сесію
- `GET /api/v1/host` — інформація про хост
- `GET /metrics` — Prometheus метрики
- `GET /healthz` — health check

**Не реалізовано (F2):**
- `POST /api/v1/containers` — створення контейнера
- `DELETE /api/v1/containers/:name` — видалення
- `POST /api/v1/containers/:name/start` — запуск
- `POST /api/v1/containers/:name/stop` — зупинка
- `GET /api/v1/containers/:name/console` — WebSocket консоль
- `GET /api/v1/containers/:name/stats` — статистика
- snapshots, export, import — через API

**Пріоритет:** Середній. Read-only API корисний для моніторингу, але без write API `crated` обмежений.

---

## 3. Мережа — недостатні можливості

### 3.1 Міжконтейнерна комунікація
Зараз контейнери на одному bridge можуть спілкуватися через L2, але немає:
- Іменування контейнерів для DNS-резолюції між jail
- Вбудованого DNS-сервісу для `.crate` доменної зони
- Мережевих політик між контейнерами (allow/deny container-to-container)

### 3.2 Автоматичне створення bridge
Якщо bridge не існує — помилка. BastilleBSD створює bridge автоматично. Додати опцію `auto_create_bridge: true` в `crate.yml`.

### 3.3 IP-пул для named networks
Named networks визначають gateway, bridge, VLAN — але не мають діапазону IP. Додати `ip_range: 192.168.1.100-192.168.1.200` для автоматичного призначення IP при `ip: auto`.

### 3.4 WireGuard/IPsec тунелі
Контейнери без вбудованої підтримки VPN-тунелів між хостами. Для multi-host deployment це обмеження.

---

## 4. Управління життєвим циклом

### 4.1 Restart policy
Немає автоматичного перезапуску контейнера при аварійному завершенні. Додати:
```yaml
restart:
    policy: on-failure   # never, on-failure, always
    max_retries: 3
    delay: 5s
```

### 4.2 Health checks
Немає перевірки стану працюючого контейнера:
```yaml
healthcheck:
    command: /usr/local/bin/curl -f http://localhost/healthz
    interval: 30s
    timeout: 5s
    retries: 3
```

### 4.3 Graceful shutdown
Зараз SIGTERM → чекати → SIGKILL. Немає налаштовуваного таймауту і порядку зупинки сервісів.

### 4.4 Container dependencies
Немає `depends_on` — запуск контейнера B тільки після A.

---

## 5. Образи та реєстри

### 5.1 Локальний реєстр `.crate` образів
Немає `crate pull`, `crate push`, `crate search`. Контейнери створюються лише локально з spec.

### 5.2 Кешування базової системи
`base.txz` завантажується кожного разу при `create`. Додати кешування в `/var/cache/crate/base/` з перевіркою SHA256.

### 5.3 Layered images
Немає шарів як у Docker. Кожен `.crate` — монолітний архів. Розглянути ZFS-based layering через clones.

---

## 6. Моніторинг та метрики

### 6.1 `crate stats` команда
Немає real-time статистики запущених контейнерів (CPU, memory, network I/O, disk I/O). `rctl -u` дає дані — потрібна лише презентація.

### 6.2 Container events/logging
Немає журналу подій контейнерів (start, stop, crash, OOM). `crated` збирає метрики, але не зберігає історію.

### 6.3 Resource usage in `crate list`
`crate list` показує тільки jid/name. Додати колонки CPU%, MEM, UPTIME, NET_MODE.

---

## 7. Безпека

### 7.1 Container image signing
Немає підпису `.crate` архівів. SHA256 є при export/import, але немає криптографічного підпису.

### 7.2 Runtime security profiles
`security_advanced` парсить Capsicum, MAC bsdextended, MAC portacl, hide_other_jails — але перевірити чи всі ці фічі мають runtime реалізацію в `run.cpp`.

### 7.3 Rootless containers
Crate встановлюється як setuid root (04755). Розглянути можливість rootless jail через `jail(8)` з `allow.nfds`.

### 7.4 Audit logging
Немає аудит-логу: хто запустив який контейнер, коли, з якими параметрами.

---

## 8. UX та CLI

### 8.1 `crate stop` команда
Немає явної команди зупинки. Контейнер зупиняється тільки SIGTERM до процесу `crate run`. Додати `crate stop TARGET`.

### 8.2 `crate restart` команда
Відсутня.

### 8.3 `crate logs` команда
Немає перегляду логів контейнера. Логи пишуться в `/var/log/crate/` але немає зручного CLI.

### 8.4 `crate top` — live resource monitor
Аналог `docker top` / `htop` для контейнерів.

### 8.5 `crate inspect` — детальний dump конфігурації
JSON-вивід повної конфігурації запущеного контейнера (spec, runtime params, network, mounts).

### 8.6 Tab completion
`completions/crate.sh` існує — перевірити повноту (всі 11 команд + subcommands).

### 8.7 `crate update` — оновлення базової системи в контейнері
Без перестворення контейнера — `freebsd-update` або `pkg upgrade` всередині jail.

---

## 9. Hub / Multi-host

### 9.1 Hub web dashboard (hub/web/)
Директорія порожня. Потрібен мінімальний HTML/JS dashboard:
- Список нод і їх стан
- Список контейнерів по нодах
- Метрики CPU/RAM
- Кнопки start/stop (після F2 API)

### 9.2 Hub container migration
Немає переміщення контейнера між хостами. Потрібно: `crate export` → transfer → `crate import` з автоматизацією.

### 9.3 Hub scheduling
Немає автоматичного розміщення контейнера на найменш завантаженому хості.

---

## 10. Тестування

### 10.1 Unit tests
Немає unit тестів (тільки integration тести в `tests/`). Потрібні unit тести для:
- Spec parsing (spec.cpp)
- Config loading (config.cpp)
- Network calculation (epair IP assignment)
- MAC generation (SHA-256)
- Spec merging (mergeSpecs)
- Port range parsing

### 10.2 CI/CD
Перевірити наявність CI (GitHub Actions, CircleCI). Потрібен автоматичний build + test pipeline.

---

## 11. Документація

### 11.1 Man page для crated
`crated` не має man page. Потрібен `crated.8` з описанням конфігурації, API endpoints, Prometheus метрик.

### 11.2 Man page для crate-hub
`crate-hub` не має man page. Потрібен `crate-hub.8`.

### 11.3 CHANGELOG
Немає файлу CHANGELOG.md з історією версій.

### 11.4 Contributing guide
Немає CONTRIBUTING.md.

---

## 12. Збірка та пакування

### 12.1 FreeBSD port
`Makefile` має `install` target, але перевірити актуальність порту `/usr/ports/sysutils/crate`.

### 12.2 pkg-message
При встановленні через pkg — інформація про початкове налаштування (VIMAGE, bridge setup).

### 12.3 cmake/meson
Makefile ручний. Розглянути cmake або meson для кращої крос-платформної збірки.

---

## Пріоритизація

### Висока (баги та quick wins)
1. Виправити `pkg/add` abort → нормальна помилка
2. `crate stop TARGET` команда
3. `crate stats` команда (rctl дані вже є)
4. Кешування base.txz
5. `crate list` з колонками CPU/MEM/UPTIME
6. CHANGELOG.md

### Середня (функціональність)
7. Restart policy (on-failure, always)
8. Health checks
9. Auto-create bridge
10. IP pool для named networks
11. `crate logs` команда
12. Unit тести для spec/config parsing
13. `crated` F2 write API
14. Hub web dashboard

### Низька (nice-to-have)
15. Container image signing
16. Inter-container DNS
17. WireGuard тунелі
18. Rootless containers
19. Container migration
20. Hub scheduling
21. Layered images
