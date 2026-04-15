# Роадмап тестування проекту Crate

## Поточний стан тестування

### Що є зараз

- **`tests/ci-verify.sh`** — 2064 рядки, 29+ тестових секцій (T01–T29)
- **GitHub Actions CI** — збірка і тести на FreeBSD 14.2 та 15.0
- **Тип тестів:** source-level grep перевірки + compile-time верифікація + runtime integration
- **Запуск:** `sudo sh tests/ci-verify.sh .`

### Проблеми поточного підходу

1. **Монолітний скрипт** — всі 2000+ рядків в одному файлі, важко підтримувати
2. **Немає юніт-тестів** — C++ код не має unit test framework (gtest/catch2)
3. **Grep-based тести** — перевіряють наявність рядків у коді, а не поведінку
4. **Немає тестів для нових фаз** — фази 1–6 не покриті тестами
5. **Немає тестів API** — daemon REST endpoints не тестуються
6. **Немає fuzzing** — YAML парсер і мережеві парсери не fuzz-тестовані
7. **Немає performance тестів** — baseline для порівняння native vs shell

---

## Рівні тестування

```
┌─────────────────────────────────────────────────┐
│  E2E (end-to-end)                               │
│  Повний цикл: create → run → interact → stop    │
├─────────────────────────────────────────────────┤
│  Integration                                    │
│  Кросс-модульна взаємодія (jail+net+zfs)        │
├─────────────────────────────────────────────────┤
│  Component                                      │
│  Окремі модулі (ipfw_ops, zfs_ops, spec parse)  │
├─────────────────────────────────────────────────┤
│  Unit                                           │
│  Функції та класи (IP pool, CIDR, port ranges)   │
└─────────────────────────────────────────────────┘
```

---

## Фаза T1: Юніт-тести (C++ gtest)

**Мета:** Покрити чисту логіку без root/jail залежностей

### T1.1 Налаштування gtest framework

**Файли:**
- `tests/unit/CMakeLists.txt` або секція `test` у `Makefile`
- `tests/unit/main.cpp` — gtest_main

**Дії:**
```makefile
# Makefile додати:
TEST_SRCS = tests/unit/test_spec.cpp tests/unit/test_util.cpp ...
TEST_LIBS = -lgtest -lgtest_main -lpthread
test: $(TEST_OBJS)
	$(CXX) $(CXXFLAGS) -o tests/unit/run_tests $(TEST_OBJS) $(LIB_OBJS) $(TEST_LIBS)
	./tests/unit/run_tests
```

### T1.2 Тести парсингу spec

**Файл:** `tests/unit/test_spec.cpp`

```
Тест-кейси:
- parseSpec() з валідним YAML → коректний Spec об'єкт
- parseSpec() з невалідним YAML → Exception
- parsePortRange("8080") → {8080, 8080}
- parsePortRange("8080-8090") → {8080, 8090}
- parsePortRange("abc") → Exception
- substituteVars("${NAME}-app", {NAME: "web"}) → "web-app"
- substituteVars("no-vars", {}) → "no-vars"
- mergeSpecs(base, overlay) → правильне злиття
- preprocess() → правильне розкриття шаблонів
- validate() → помилки при некоректних значеннях
- Секції scripts: parseScriptsSection() з різними ключами
- Парсинг network policy YAML (Фаза 1)
- Парсинг restart policy YAML (Фаза 4)
- Парсинг disk_quota (Фаза 2)
```

### T1.3 Тести утиліт

**Файл:** `tests/unit/test_util.cpp`

```
Тест-кейси:
- splitString("a,b,c", ",") → {"a","b","c"}
- splitString("", ",") → {}
- shellQuote("hello world") → "'hello world'"
- shellQuote("it's") → правильне екранування
- safePath("/var/jails/test", "/var/jails/", "test") → OK
- safePath("/../etc/passwd", "/var/jails/", "test") → Exception
- stripTrailingSpace("hello  ") → "hello"
- isUrl("https://example.com") → true
- isUrl("/local/path") → false
- sha256hex("test") → відомий хеш
- randomHex(16) → 32 hex символи
```

### T1.4 Тести IP pool (Фаза 1)

**Файл:** `tests/unit/test_ip_pool.cpp`

```
Тест-кейси:
- parseCIDR("172.20.0.0/24") → base=172.20.0.0, mask=24
- allocateIP(pool, 0) → 172.20.0.2 (.1 зарезервовано для gw)
- allocateIP(pool, 253) → 172.20.0.254 (остання адреса)
- allocateIP(pool, 254) → Exception (вихід за межі /24)
- parseCIDR("10.0.0.0/8") → великий пул
- parseCIDR("invalid") → Exception
```

### T1.5 Тести YAML stack парсингу

**Файл:** `tests/unit/test_stack.cpp`

```
Тест-кейси:
- parseStackFile() з повним YAML → коректна ParsedStack
- Topological sort залежностей: A→B→C → порядок C,B,A
- Циклічні залежності → Exception
- buildHostsEntries() → правильний /etc/hosts формат
- collectContainerIPs() → правильна карта name→ip
- Network policy парсинг з default deny/allow
```

### T1.6 Тести lifecycle (Фаза 4)

**Файл:** `tests/unit/test_lifecycle.cpp`

```
Тест-кейси:
- Restart policy парсинг: "on-failure" → RestartPolicy::OnFailure
- Restart policy парсинг: "always" → RestartPolicy::Always
- shouldRestart(OnFailure, exitCode=1) → true
- shouldRestart(OnFailure, exitCode=0) → false
- shouldRestart(No, exitCode=1) → false
- shouldRestart(Always, exitCode=0) → true
- Max retries enforcement
- Delay calculation between restarts
```

---

## Фаза T2: Компонентні тести

**Мета:** Тестувати окремі модулі з мок-об'єктами

### T2.1 Тести ZFS operations (mock)

**Файл:** `tests/component/test_zfs_ops.cpp`

```
Тест-кейси (без реального ZFS):
- setRefquota() формує правильну команду
- snapshot() формує правильне ім'я
- clone() формує правильний виклик
- listSnapshots() парсить вивід zfs list
- getMountpoint() парсить вивід zfs get
- isEncrypted() розпізнає encrypted datasets
- send()/recv() правильно налаштовують fd
```

### T2.2 Тести IPFW operations (Фаза 6)

**Файл:** `tests/component/test_ipfw_ops.cpp`

```
Тест-кейси:
- addRule() — правильна структура ip_fw3
- deleteRule() — правильний rule number
- configureNat() — правильний NAT instance
- addPortForward() — правильні redirect параметри
- Rule numbering: base + slot*slotSize + offset
- Shell fallback при відсутності IP_FW3
```

### T2.3 Тести MAC operations (Фаза 6)

**Файл:** `tests/component/test_mac_ops.cpp`

```
Тест-кейси:
- addUgidfwRule() — правильний формат правила
- removeUgidfwRules(jid) — правильний фільтр
- setPortaclRules() — правильний формат
- Ioctl fallback при відсутності /dev/ugidfw
```

### T2.4 Тести мережевих політик (Фаза 1)

**Файл:** `tests/component/test_net_policy.cpp`

```
Тест-кейси:
- Default deny → генерує deny all правило
- Allow rule from→to:port → правильне ipfw правило
- Multiple rules → правильний порядок
- Rule slot allocation
- Cleanup при зупинці контейнера
```

### T2.5 Тести daemon auth (Фаза 5)

**Файл:** `tests/component/test_auth.cpp`

```
Тест-кейси:
- getpeereid() повертає root → дозволено
- getpeereid() повертає non-root → заборонено
- Unix socket → auth працює
- TCP socket → auth пропускається або забороняється
```

### T2.6 Тести Prometheus метрик (Фаза 2/5)

**Файл:** `tests/component/test_metrics.cpp`

```
Тест-кейси:
- collectMetrics() → правильний Prometheus формат
- Per-container gauge: crate_container_memory_bytes{name="x"} 123
- Counter vs gauge типи
- Help/type коментарі
- Порожній стан (0 контейнерів)
```

---

## Фаза T3: Інтеграційні тести (потребують root)

**Мета:** Реальна взаємодія з FreeBSD підсистемами

### T3.1 Розширення ci-verify.sh для нових фаз

**Файл:** `tests/ci-verify.sh` — додати секції T30–T45

```
T30: Network policy — source-level перевірка NetworkPolicy struct
T31: IP pool allocator — source-level перевірка CIDR парсингу
T32: DNS per-stack — unbound конфігурація генерується
T33: RCTL verification — source-level перевірка rctl -l
T34: OOM diagnostics — diagnoseExitReason присутня
T35: ZFS refquota — setRefquota() в zfs_ops
T36: VM shared bridge — connectToSharedBridge() в vm_run
T37: Virtio-9p volumes — source-level перевірка
T38: crate stats — підкоманда зареєстрована
T39: crate logs — підкоманда зареєстрована
T40: crate stop/restart — підкоманди зареєстровані
T41: Restart policies — RestartPolicy struct в spec
T42: REST API F2 — POST/DELETE endpoints в routes.cpp
T43: Unix socket auth — getpeereid в auth.cpp
T44: Native IPFW — IP_FW3 або setsockopt в ipfw_ops
T45: base.txz cache — cache dir і SHA-256 перевірка
```

### T3.2 Jail integration тести

**Файл:** `tests/integration/test_jail.sh`

```
Тест-кейси (потребують root + CAN_JAIL):
- Створити jail → перевірити jls
- Застосувати RCTL ліміти → перевірити rctl -l
- OOM: встановити memoryuse=1M, запустити malloc bomb → exit 137
- Restart policy: on-failure + exit 1 → перезапуск
- Stop: SIGTERM → graceful shutdown
- Stop: timeout → SIGKILL
```

### T3.3 Мережеві integration тести

**Файл:** `tests/integration/test_network.sh`

```
Тест-кейси (потребують root + VIMAGE):
- Створити epair → ping між host і jail
- Bridge: два jail на одному bridge → ping між ними
- NAT: jail → internet (curl httpbin.org)
- Network policy deny: jail A →/→ jail B
- Network policy allow: jail A → jail B:8080
- IP pool: автоматичне призначення → правильні адреси
```

### T3.4 ZFS integration тести

**Файл:** `tests/integration/test_zfs.sh`

```
Тест-кейси (потребують root + HAS_ZFS):
- Створити dataset → snapshot → rollback
- Clone dataset → перевірити дані
- setRefquota 10M → dd 20M → fails
- Export → import → дані збережені
- Encrypted dataset → key load/unload
```

### T3.5 Stack integration тести

**Файл:** `tests/integration/test_stack.sh`

```
Тест-кейси (потребують root + VIMAGE + ZFS):
- Stack з 2 контейнерами → /etc/hosts правильні
- DNS per-stack: unbound запущений → резолвінг працює
- Network policy: deny + allow → правильна фільтрація
- Volumes: shared volume → файл видно в обох контейнерах
- Depends: B depends A → A запускається першим
```

### T3.6 API integration тести

**Файл:** `tests/integration/test_api.sh`

```
Тест-кейси (потребують запущений crated):
- GET /healthz → 200
- GET /api/v1/containers → JSON список
- POST /api/v1/containers → створення
- POST /api/v1/containers/:name/stop → зупинка
- GET /metrics → Prometheus формат
- Unix socket auth: root → дозволено
```

---

## Фаза T4: E2E тести

**Мета:** Повний сценарій від YAML до працюючого стеку

### T4.1 Сценарій: web-app-db стек

**Файл:** `tests/e2e/test_web_stack.sh`

```
1. crate create web.yml → створити контейнер
2. crate create db.yml → створити контейнер
3. Stack up → обидва контейнери запущені
4. web → ping db → OK
5. web → curl db:5432 → OK
6. crate stats web → показує метрики
7. crate logs web → показує логи
8. crate stop web → graceful stop
9. crate restart web → back online
10. Stack down → все зупинено і очищено
```

### T4.2 Сценарій: OOM та restart

```
1. Створити контейнер з memoryuse=50M
2. Запустити malloc bomb
3. Перевірити exit 137
4. Перевірити лог "OOM"
5. Restart policy on-failure → автоперезапуск
6. Max retries → зупинка після N спроб
```

### T4.3 Сценарій: export/import з encryption

```
1. Створити encrypted контейнер
2. Записати дані
3. crate export → .crate файл
4. crate import → новий контейнер
5. Перевірити дані збережені
6. Перевірити encryption active
```

---

## Фаза T5: Спеціалізовані тести

### T5.1 Security тести

```
- Directory traversal: safePath з "../" → Exception
- Shell injection: shellQuote з спецсимволами → безпечно
- Symlink attacks: O_NOFOLLOW перевірка
- Jail escape: securelevel > 0 → заборонено
- MAC enforcement: ugidfw правила → ефективні
```

### T5.2 Fuzzing

```
- YAML spec fuzzer (AFL++/libFuzzer): випадковий YAML → parseSpec() не crash
- Port range fuzzer: випадкові рядки → parsePortRange() не crash
- CIDR fuzzer: випадкові рядки → parseCIDR() не crash
- Daemon request fuzzer: випадкові HTTP → не crash
```

### T5.3 Performance тести

```
- Jail create/destroy latency: < 500ms
- Epair create/destroy latency: < 100ms
- IPFW native vs shell: порівняння throughput
- MAC ioctl vs shell: порівняння throughput
- 100 concurrent containers: stability
- Stack with 10 containers: startup time
```

---

## CI/CD інтеграція

### Оновлення `.github/workflows/freebsd-build.yml`

```yaml
jobs:
  unit-tests:
    # Запуск на кожен push (швидко, без root)
    steps:
      - make test-unit

  integration-tests:
    # Запуск на кожен push (потребує root)
    needs: unit-tests
    steps:
      - sudo sh tests/ci-verify.sh .
      - sudo sh tests/integration/run_all.sh

  e2e-tests:
    # Запуск тільки на PR до master
    needs: integration-tests
    if: github.event_name == 'pull_request'
    steps:
      - sudo sh tests/e2e/run_all.sh
```

### Матриця тестування

```
            │ FreeBSD 14.2 │ FreeBSD 15.0 │
────────────┼──────────────┼──────────────┤
Unit        │      ✅      │      ✅      │
Component   │      ✅      │      ✅      │
Integration │      ✅      │      ✅      │
E2E         │   PR only    │   PR only    │
Fuzzing     │   Nightly    │   Nightly    │
Performance │   Weekly     │   Weekly     │
```

---

## Пріоритети імплементації

| # | Задача | Пріоритет | Зусилля | Цінність |
|---|--------|-----------|---------|----------|
| T1.1 | gtest framework setup | 🔴 Критичний | 2h | Фундамент |
| T1.2 | test_spec.cpp | 🔴 Критичний | 4h | Найбільший модуль |
| T1.3 | test_util.cpp | 🔴 Критичний | 2h | Базові утиліти |
| T1.4 | test_ip_pool.cpp | 🟡 Високий | 2h | Фаза 1 |
| T1.5 | test_stack.cpp | 🟡 Високий | 3h | Stack orchestration |
| T1.6 | test_lifecycle.cpp | 🟡 Високий | 2h | Фаза 4 |
| T3.1 | ci-verify T30–T45 | 🔴 Критичний | 4h | Regression для фаз |
| T3.2 | test_jail.sh | 🟡 Високий | 4h | Core functionality |
| T3.3 | test_network.sh | 🟡 Високий | 6h | Найскладніший модуль |
| T5.2 | Fuzzing setup | 🟢 Середній | 8h | Security |
| T5.3 | Performance baseline | 🟢 Середній | 4h | Optimization validation |
