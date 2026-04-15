# Аналіз повноти покриття фаз реалізації

## Зведена таблиця покриття (після виправлення прогалин)

| Фаза | Гілка | Коміти | Файли | Покриття | Залишкові прогалини |
|------|-------|--------|-------|----------|---------------------|
| 1. Мережа | `phase-1-networking` | 2 (+492 LOC) | 2 | ✅ Добре | `run_services.cpp` інтеграція |
| 2. Ресурси | `phase-2-resources` | 2 (+349 LOC) | 7 | ✅ Добре | devd інтеграція (документовано) |
| 3. Jail↔VM | `phase-3-jail-vm` | 2 (+383 LOC) | 8 | ✅ Добре | Повна NFS реалізація |
| 4. CLI | `phase-4-cli-commands` | 2 (+679 LOC) | 9 | ✅ Добре | Юніт-тести (див. testing-roadmap) |
| 5. Daemon | `phase-5-daemon-api` | 2 (+847 LOC) | 4 | ✅ Добре | WebSocket (chunked streaming замість нього) |
| 6. Оптимізація | `phase-6-optimization` | 2 (+402 LOC) | 6 | ✅ Добре | Бенчмарки (таймінг доданий) |

---

## Детальний аналіз по фазах

### Фаза 1: Мережа

**Реалізовано (коміт 1):**
- ✅ 1.1 DNS per-stack (unbound конфігурація, запуск, resolv.conf)
- ✅ 1.2 Network policies (NetworkPolicy struct, ipfw правила allow/deny)
- ✅ 1.3 IP pool allocator (CIDR парсинг, послідовне виділення)

**Виправлено (коміт 2):**
- ✅ Валідація CIDR — ERR на невалідний subnet, перевірка prefix length 8–30
- ✅ Обробка помилок unbound — waitpid(WNOHANG) перевірка після запуску
- ✅ DNS hot-reload — `updateStackDns()` з перегенерацією конфігу + SIGHUP
- ✅ Ізоляція між стеками — блокування трафіку з чужих subnet при default=deny
- ✅ Валідація network policy — перевірка action (allow/deny) і proto (tcp/udp)
- ✅ WARN на невідомі контейнери в policy rules
- ✅ Унікальний pidfile per-stack

**Залишкові прогалини:**
- ⚠️ `run_services.cpp` не змінено — unbound управляється з stack.cpp напряму

### Фаза 2: Ресурси

**Реалізовано (коміт 1):**
- ✅ 2.1 RCTL верифікація після застосування лімітів
- ✅ 2.2 OOM діагностика (diagnoseExitReason)
- ✅ 2.3 Per-container Prometheus метрики
- ✅ 2.4 ZFS refquota

**Виправлено (коміт 2):**
- ✅ `isOomKill()` і `wasKilledByRctl()` — хелпери для restart policy інтеграції
- ✅ `getRctlUsagePercent()` — моніторинг тиску пам'яті (% від ліміту)
- ✅ devd інтеграція задокументована як майбутній шлях (post-mortem поточний підхід)
- ✅ `parseRctlUsage()` — витягнуто для реюзу з `crate stats` (Фаза 4)
- ✅ Валідація `disk_quota` — перевірка формату (число + G/M/T/K суфікс)

**Залишкові прогалини:**
- ⚠️ Реальна devd інтеграція (документовано, не реалізовано)

### Фаза 3: Jail ↔ VM

**Реалізовано (коміт 1):**
- ✅ 3.1 Спільний bridge (connectToSharedBridge)
- ✅ 3.2 Спільні volumes через virtio-9p

**Виправлено (коміт 2):**
- ✅ **3.3 DNS між jail і VM** — `configureVmDns()` через shared resolv.conf
- ✅ VM stack інтеграція — `vm_stack.h/cpp` з `registerVmInStack()`
- ✅ Cloud-init для 9p — `generateCloudInitFor9p()` з mount скриптами
- ✅ NFS fallback — `shareMethod` поле (9p/nfs) в SharedVolume

**Залишкові прогалини:**
- ⚠️ NFS серверна частина (тільки spec, не runtime)

### Фаза 4: CLI команди

**Реалізовано (коміт 1):**
- ✅ 4.1 `crate stats` (RCTL usage, --json)
- ✅ 4.2 `crate logs` (--follow, --tail)
- ✅ 4.3 `crate stop/restart` (SIGTERM→SIGKILL, timeout)
- ✅ 4.4 Restart policies (on-failure, always, unless-stopped)

**Виправлено (коміт 2):**
- ✅ `lifecycle.cpp` додано до Makefile LIB_SRCS
- ✅ `lifecycle.h` header створений з деклараціями всіх функцій
- ✅ --help текст для stats/logs/stop/restart підкоманд
- ✅ Мережевий I/O в stats (NET_IN/NET_OUT через netstat -I)
- ✅ Головне usage() оновлено зі списком нових підкоманд

**Залишкові прогалини:**
- ⚠️ Юніт-тести (див. testing-roadmap.md T1.6)

### Фаза 5: Daemon і API

**Реалізовано (коміт 1):**
- ✅ 5.1 REST API F2 ендпоінти (POST/DELETE create/destroy, start/stop)
- ✅ 5.2 Per-container Prometheus метрики
- ✅ 5.3 Unix socket auth (getpeereid)
- ✅ 5.4 SNMP AgentX протокол

**Виправлено (коміт 2):**
- ✅ Auth middleware — перевірка авторизації на всіх мутуючих ендпоінтах
- ✅ Rate limiting — 10 req/s мутуючі, 100 req/s read, відповідь 429
- ✅ Streaming logs — chunked transfer encoding для `?follow=true`
- ✅ SNMP MIB OIDs — повне OID дерево з PEN 59999

**Залишкові прогалини:**
- ⚠️ Повний WebSocket замість chunked streaming (достатньо для більшості випадків)

### Фаза 6: Оптимізація

**Реалізовано (коміт 1):**
- ✅ 6.1 Нативний IPFW API (setsockopt IP_FW3)
- ✅ 6.2 Нативний MAC ioctl (/dev/ugidfw)
- ✅ 6.3 Кешування base.txz (SHA-256)

**Виправлено (коміт 2):**
- ✅ Runtime detection — `useNativeApi()` з кешованим тестом сокету
- ✅ `/dev/ugidfw` перевірка — `useNativeUgidfw()` з access() check
- ✅ Cache eviction — `cleanBaseCache(maxEntries=5)` + warning > 5GB
- ✅ Performance logging — std::chrono таймінг для native vs shell

**Залишкові прогалини:**
- ⚠️ Окремий бенчмарк suite (логування додано, suite в testing-roadmap T5.3)

---

## Крос-фазові інтеграції

| Зв'язок | Статус | Деталі |
|---------|--------|--------|
| Фаза 2.2 (OOM) → Фаза 4.4 (restart policy) | ✅ Виправлено | `isOomKill()` + `wasKilledByRctl()` хелпери для restart |
| Фаза 1.1 (DNS) → Фаза 3.3 (jail↔VM DNS) | ✅ Виправлено | `configureVmDns()` + `registerVmInStack()` |
| Фаза 4.1 (stats) → Фаза 5.2 (Prometheus) | ✅ Виправлено | `parseRctlUsage()` — спільна функція парсингу |
| Фаза 4.3 (stop) → Фаза 5.1 (API stop) | ✅ Виправлено | Auth middleware + пряма інтеграція |
| Фаза 6.1 (IPFW native) → Фаза 1.2 (network policies) | ⚠️ Часткове | Runtime detection визначає API, policies використовують IpfwOps:: |

---

## Залишкові функції (не в жодній фазі)

1. **VM ↔ VM комунікація** — ізольовані, навіть в одному стеку
2. **Rolling updates** — оновлення контейнерів без downtime
3. **Config reload** — зміна spec без перестворення контейнера
4. **Multi-host** — розподілені контейнери на декількох хостах
5. **Container image registry** — pull/push .crate файлів з репозиторію

---

## Загальна статистика виправлень

| Фаза | Коміт 1 (LOC) | Коміт 2 (LOC) | Разом | Нових файлів |
|------|---------------|---------------|-------|-------------|
| 1 | +402 | +90 | +492 | 0 |
| 2 | +173 | +176 | +349 | 0 |
| 3 | +109 | +274 | +383 | 2 (vm_stack.h/cpp) |
| 4 | +514 | +165 | +679 | 1 (lifecycle.h) |
| 5 | +546 | +301 | +847 | 0 |
| 6 | +219 | +183 | +402 | 1 (ipfw_ops.h доповнення) |
| **Всього** | **+1963** | **+1189** | **+3152** | **4** |
