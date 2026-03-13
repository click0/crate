# Аналіз повноти покриття фаз реалізації

## Зведена таблиця покриття

| Фаза | Гілка | LOC+ | Файли | Покриття | Прогалини |
|------|-------|------|-------|----------|-----------|
| 1. Мережа | `phase-1-networking` | +402 | 2 | ⚠️ Часткове | Немає `run_services.cpp`, unbound конфіг неповний |
| 2. Ресурси | `phase-2-resources` | +173 | 7 | ✅ Добре | Мінорні прогалини |
| 3. Jail↔VM | `phase-3-jail-vm` | +109 | 4 | ⚠️ Часткове | Немає 3.3 DNS, немає stack.cpp |
| 4. CLI | `phase-4-cli-commands` | +514 | 8 | ✅ Добре | Немає юніт-тестів |
| 5. Daemon | `phase-5-daemon-api` | +546 | 4 | ✅ Добре | Немає error handling в routes |
| 6. Оптимізація | `phase-6-optimization` | +219 | 3 | ⚠️ Часткове | Тільки shell fallback замість нативного |

---

## Детальний аналіз по фазах

### Фаза 1: Мережа

**Реалізовано:**
- ✅ 1.1 DNS per-stack (unbound конфігурація, запуск, resolv.conf)
- ✅ 1.2 Network policies (NetworkPolicy struct, ipfw правила allow/deny)
- ✅ 1.3 IP pool allocator (CIDR парсинг, послідовне виділення)

**Прогалини:**
- ❌ `run_services.cpp` не змінено — запуск/зупинка unbound залишилась в stack.cpp, не інтегрована з загальною системою сервісів
- ❌ Немає обробки помилок при падінні unbound
- ❌ Немає оновлення DNS зон при гарячому додаванні/видаленні контейнерів (тільки початковий старт)
- ❌ Немає валідації CIDR (некоректний subnet не відловлюється)
- ❌ Немає ізоляції мережі між різними стеками

### Фаза 2: Ресурси

**Реалізовано:**
- ✅ 2.1 RCTL верифікація після застосування лімітів
- ✅ 2.2 OOM діагностика (diagnoseExitReason)
- ✅ 2.3 Per-container Prometheus метрики
- ✅ 2.4 ZFS refquota

**Прогалини:**
- ❌ Немає devd інтеграції для real-time OOM подій
- ❌ `diagnoseExitReason()` не інтегрована з restart policy (Фаза 4)
- ❌ Memory pressure monitoring — тільки usage, не pressure

### Фаза 3: Jail ↔ VM

**Реалізовано:**
- ✅ 3.1 Спільний bridge (connectToSharedBridge)
- ✅ 3.2 Спільні volumes через virtio-9p

**Прогалини:**
- ❌ **3.3 DNS між jail і VM повністю відсутній** — задача вказана як залежна від 1.1, але код не написаний
- ❌ `stack.cpp` не змінений — VM entries не підтримуються в stack файлах
- ❌ Немає автоматичного mount_9p в гостьовій ОС (потрібен скрипт)
- ❌ Немає fallback на NFS якщо virtio-9p недоступний

### Фаза 4: CLI команди

**Реалізовано:**
- ✅ 4.1 `crate stats` (RCTL usage, --json)
- ✅ 4.2 `crate logs` (--follow, --tail)
- ✅ 4.3 `crate stop/restart` (SIGTERM→SIGKILL, timeout)
- ✅ 4.4 Restart policies (on-failure, always, unless-stopped)

**Прогалини:**
- ❌ `lifecycle.cpp` — новий файл, не доданий до Makefile LIB_SRCS
- ❌ `args.cpp` — нові підкоманди додані, але --help текст не оновлений
- ❌ `crate stats` не показує мережевий I/O (тільки RCTL метрики)
- ❌ Немає `crate top` для інтерактивного перегляду (htop-стиль)

### Фаза 5: Daemon і API

**Реалізовано:**
- ✅ 5.1 REST API F2 ендпоінти (POST/DELETE create/destroy, start/stop)
- ✅ 5.2 Per-container Prometheus метрики
- ✅ 5.3 Unix socket auth (getpeereid)
- ✅ 5.4 SNMP AgentX протокол

**Прогалини:**
- ❌ Routes не перевіряють авторизацію перед кожним ендпоінтом (auth написаний, але не підключений до routes)
- ❌ Немає rate limiting на API
- ❌ Немає WebSocket для `logs --follow` через API
- ❌ SNMP AgentX — тільки каркас, немає повної MIB реєстрації

### Фаза 6: Оптимізація

**Реалізовано:**
- ✅ 6.1 Нативний IPFW API (setsockopt IP_FW3)
- ✅ 6.2 Нативний MAC ioctl (/dev/ugidfw)
- ✅ 6.3 Кешування base.txz (SHA-256)

**Прогалини:**
- ❌ IPFW native API — код є, але переключення між native/shell fallback не автоматичне (потрібен runtime detection)
- ❌ MAC ioctl — `/dev/ugidfw` може бути відсутнім, немає перевірки
- ❌ Кеш base.txz — немає очистки старих кешованих файлів (cache eviction)
- ❌ Немає бенчмарків для порівняння native vs shell performance

---

## Відсутні крос-фазові інтеграції

| Зв'язок | Статус | Деталі |
|---------|--------|--------|
| Фаза 2.2 (OOM) → Фаза 4.4 (restart policy) | ❌ | OOM не тригерить restart |
| Фаза 1.1 (DNS) → Фаза 3.3 (jail↔VM DNS) | ❌ | VM не додаються в unbound |
| Фаза 4.1 (stats) → Фаза 5.2 (Prometheus) | ⚠️ | Дублювання коду збору метрик |
| Фаза 4.3 (stop) → Фаза 5.1 (API stop) | ⚠️ | API викликає shell замість функції |
| Фаза 6.1 (IPFW native) → Фаза 1.2 (network policies) | ❌ | Policies використовують shell ipfw |

---

## Повністю відсутні функції (не в жодній фазі)

1. **Мережева ізоляція між стеками** — немає firewall між різними stack instances
2. **VM ↔ VM комунікація** — ізольовані, навіть в одному стеку
3. **Гаряче додавання/видалення контейнерів** у запущеному стеку
4. **Backup/restore** з точками відновлення та інкрементальними бекапами
5. **Rolling updates** — оновлення контейнерів без downtime
6. **Config reload** — зміна spec без перестворення контейнера
7. **Multi-host** — розподілені контейнери на декількох хостах
8. **Container image registry** — pull/push .crate файлів з репозиторію
