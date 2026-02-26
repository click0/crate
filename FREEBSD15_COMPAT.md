# Анализ совместимости проекта `crate` с FreeBSD 15.0

**Дата анализа:** 2026-02-19
**Версия FreeBSD:** 15.0-RELEASE (выпущена 2 декабря 2025)
**Проект:** crate — контейнеризатор для FreeBSD (C++17)

---

## Общая оценка

**Степень совместимости: СРЕДНЯЯ (требуются изменения)**

Проект `crate` является нативным FreeBSD-приложением, написанным на C++17, и в целом
хорошо совместим с FreeBSD 15.0, однако имеется ряд проблем различной критичности,
требующих внимания.

---

## 1. Критические проблемы (CRITICAL)

### 1.1. URL загрузки base.txz — FTP deprecated

**Файл:** `locs.cpp:15-17`

```cpp
const std::string baseArchiveUrl = STRg("ftp://ftp1.freebsd.org/pub/FreeBSD/snapshots/"
                                        << Util::getSysctlString("hw.machine") << "/"
                                        << Util::getSysctlString("kern.osrelease")
                                        << "/base.txz");
```

**Проблема:** Проект использует `ftp://ftp1.freebsd.org/pub/FreeBSD/snapshots/` для загрузки
base.txz. В FreeBSD 15.0:

- `ftpd(8)` удалён из базовой системы
- Канонический URL изменён на `https://download.freebsd.org/`
- FTP-серверы FreeBSD постепенно выводятся из эксплуатации

Команда `fetch` (используется в `create.cpp:282`) поддерживает HTTPS, но сам URL указывает
на потенциально недоступный FTP-сервер.

Кроме того, с переходом на **pkgbase** в FreeBSD 15.0 структура дистрибутивных наборов
меняется. В FreeBSD 16 планируется полный отказ от distribution sets (base.txz, kernel.txz)
в пользу pkgbase. Для создания jail'ов через pkgbase используется:
`pkg -r /jails/myjail install FreeBSD-set-base`.

**Действие:** Заменить URL на `https://download.freebsd.org/releases/` или
`https://download.freebsd.org/snapshots/`, а в перспективе — реализовать поддержку pkgbase.

### 1.2. Бинарная несовместимость ipfw в jail'ах

**Файлы:** `run.cpp:264-338`, `create.cpp:212-216`

**Проблема:** Из ядра FreeBSD 15.0 удалён код совместимости для бинарных файлов `ipfw`
из FreeBSD 7/8 (коммит `4a77657cbc01`). При запуске контейнеров, созданных на базе
FreeBSD 14.x, на хосте с FreeBSD 15.0 `ipfw` внутри jail'а не будет работать:

```
ipfw: setsockopt(IP_FW_XDEL): Invalid argument
ipfw: getsockopt(IP_FW_XADD): Invalid argument
```

Это напрямую затрагивает сетевой стек `crate`, так как проект активно использует `ipfw`
для NAT и фильтрации трафика внутри и вне jail'а.

**Действие:** Контейнеры, созданные на FreeBSD <15.0, необходимо пересоздать с base.txz
от FreeBSD 15.0. Рекомендуется добавить проверку версии при запуске.

### 1.3. Баг TCP checksum offload в epair-интерфейсах

**Файл:** `run.cpp:230-248`

```cpp
std::string epipeIfaceA = Util::stripTrailingSpace(
    Util::runCommandGetOutput("ifconfig epair create", "create the jail epipe"));
std::string epipeIfaceB = STR(epipeIfaceA.substr(0, epipeIfaceA.size()-1) << "b");
```

**Проблема:** После обновления до FreeBSD 15.0 пользователи массово сообщают о проблемах
с сетевым доступом из VNET jail'ов через epair-интерфейсы
([Forum](https://forums.freebsd.org/threads/no-access-to-external-network-from-vnet-jails-in-15-0-release.100669/)).

Причина: epair поддерживает `TXCSUM`/`TXCSUM6` (checksum offloading) и пересылает вычисление
контрольных сумм на физический интерфейс. Если пакеты не покидают хост (jail->host или
jail->jail), контрольная сумма никогда не вычисляется, и пакеты отбрасываются.

**Действие:** После создания epair-интерфейсов добавить:
```
ifconfig epairXa -txcsum -txcsum6
ifconfig epairXb -txcsum -txcsum6
```

Также замечены проблемы с именованием интерфейсов при переносе в jail — возможно
появление `vnet0.X` вместо ожидаемого `epairXb`
([Forum](https://forums.freebsd.org/threads/epair0-behaves-like-schrodingers-cat-and-is-not-working-anymore-after-upgrading-to-15-0.101110/)).
Требуется тестирование парсинга имён интерфейсов.

---

## 2. Высокий приоритет (HIGH)

### 2.1. Jail API — новые файловые дескрипторы

**Файл:** `run.cpp:158-169`

```cpp
res = ::jail_setv(JAIL_CREATE,
  "path", jailPath.c_str(),
  "host.hostname", Util::gethostname().c_str(),
  "persist", nullptr,
  "allow.raw_sockets", optNet,
  "allow.socket_af", optNet,
  "vnet", nullptr,
  nullptr);
```

**Изменения в FreeBSD 15.0:**
- Добавлены новые syscall'ы: `jail_set(2)`, `jail_get(2)`, `jail_attach_jd(2)`,
  `jail_remove_jd(2)` для работы через файловые дескрипторы
- Устранены race conditions, связанные с использованием jail ID
- Добавлены параметры `meta` и `env` для метаданных и переменных окружения
- Поддержка `zfs.dataset` для прикрепления ZFS-датасетов

**Статус:** Существующий код с `jail_setv()` и `jail_remove()` продолжает работать
(обратная совместимость сохранена), но рекомендуется миграция на новый API для
устранения race conditions.

**Действие:** Рассмотреть миграцию на jail descriptor API для надёжности.

### 2.2. `sys/jail.h` не является C++-safe

**Файл:** `run.cpp:21-23`

```cpp
extern "C" { // sys/jail.h isn't C++-safe: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=238928
#include <sys/jail.h>
}
```

**Статус:** По имеющимся данным, баг #238928 по-прежнему не исправлен в FreeBSD 15.0.
Обёртка `extern "C"` остаётся необходимой. Требуется проверка при сборке.

### 2.3. Изменение поведения `setgroups(2)` / `getgroups(2)`

**Файлы:** `run.cpp:364-367` (использование `pw useradd`, `pw groupadd`, `pw usermod`)

**Изменение в FreeBSD 15.0:** `setgroups(2)`, `getgroups(2)` и `initgroups(3)` изменены —
effective group ID больше не включается в массив. Это может повлиять на настройку
пользователей внутри jail'а через `pw`.

**Действие:** Протестировать создание пользователей и групп внутри jail'а с FreeBSD 15.0
base, убедиться что принадлежность к группам (wheel, videoops) корректна.

---

## 3. Средний приоритет (MEDIUM)

### 3.1. `_WITH_GETLINE` — вероятно, больше не требуется

**Файл:** `util.cpp:20`

```cpp
#define _WITH_GETLINE // it breaks on 11.3 w/out this, but the manpage getline(3) doesn't mention _WITH_GETLINE
```

**Изменение:** В FreeBSD 15.0 `getline()` экспортируется по умолчанию без необходимости
определения `_WITH_GETLINE` или `_POSIX_C_SOURCE`. Определение `_WITH_GETLINE` не вызывает
ошибки, но является мёртвым кодом.

**Действие:** Можно безопасно удалить `#define _WITH_GETLINE`. Если нужна обратная
совместимость с FreeBSD <15.0, можно оставить с комментарием.

### 3.2. LLVM/Clang обновлён до версии 19.1.7

**Файл:** `Makefile:10`

```makefile
CXXFLAGS+= -Wall -std=c++17
```

**Изменение:** FreeBSD 15.0 поставляется с Clang 19.1.7 (в FreeBSD 14.0 был Clang 16.0.6).
Clang 19 вводит новые предупреждения и ужесточает проверки.

**Потенциальные проблемы:**
- Новые предупреждения при `-Wall` (особенно для C-style casts, неявных преобразований)
- Более строгая проверка C++17 conformance
- GoogleTest (если используется) теперь требует C++14 минимум

**Действие:** Выполнить тестовую сборку и проверить новые предупреждения/ошибки.

### 3.3. Изменение поведения bridge-интерфейсов

**Файл:** `run.cpp:230-248` (epair-интерфейсы)

**Изменение:** В FreeBSD 15.0 bridge начал разрешать IP только на самом bridge, а не
на member-интерфейсах. Это может повлиять на сетевую конфигурацию VNET jail'ов, если
используются bridge-интерфейсы.

**Статус:** `crate` использует epair напрямую (без bridge), поэтому данное изменение
скорее всего не затрагивает проект напрямую, но требует внимания при расширении
сетевых возможностей.

### 3.4. VNET sysctl как loader tunables

**Файл:** `run.cpp:109-115`

```cpp
if (Util::getSysctlInt("kern.features.vimage") == 0)
    ERR(...)
if (Util::getSysctlInt("net.inet.ip.forwarding") == 0)
    Util::setSysctlInt("net.inet.ip.forwarding", 1);
```

**Изменение:** VNET sysctl переменные теперь могут быть loader tunables (расширение
`CTLFLAG_TUN`). Это означает, что `net.inet.ip.forwarding` и подобные переменные могут
быть установлены через loader.conf ещё до загрузки ядра.

**Действие:** Функциональность не сломана, но стоит обновить документацию.

---

## 4. Низкий приоритет (LOW)

### 4.1. Совместимость `nmount()` — OK (улучшено)

**Файл:** `mount.cpp:28-59`

`nmount()` — стабильный FreeBSD syscall. В FreeBSD 15.0 исправлена обработка флага
`MNT_IGNORE` для devfs, fdescfs и nullfs — флаг теперь корректно сохраняется через
`nmount(2)`, что уменьшает шум от `df(1)` и `mount(8)` при контейнерных рабочих нагрузках.
API и сигнатура вызова не изменились.

### 4.2. `O_EXLOCK` — OK

**Файл:** `ctx.cpp:34`

```cpp
ctx->fd = ::open(file().c_str(), O_RDWR|O_CREAT|O_EXLOCK, 0600);
```

`O_EXLOCK` — стандартный BSD-флаг, изменений не обнаружено. Работает корректно.

### 4.3. `sysctlbyname()` — OK

**Файлы:** `util.cpp:151-170`

Syscall `sysctlbyname()` не претерпел изменений. `sysctl(8)` утилита получила
дополнительные функции (jail attachment, фильтрация vnet/prison переменных), но API
для программного доступа стабилен.

### 4.4. `kldload()` — OK

**Файл:** `util.cpp:172-174`

API `kldload()` стабилен, изменений не обнаружено.

### 4.5. `chflags()` — OK

**Файл:** `util.cpp:331-353`

Системный вызов `chflags()` стабилен, изменений не обнаружено.

### 4.6. `fdclose()` — OK

**Файл:** `util.cpp:276`

```cpp
if (::fdclose(file, nullptr) != 0)
```

`fdclose()` (появился в FreeBSD 11.0) по-прежнему доступен в FreeBSD 15.0.

### 4.7. `readdir_r(3)` — deprecated

Проект не использует `readdir_r()` напрямую (вместо этого используется
`std::filesystem::directory_iterator`), но если какая-либо зависимость использует
`readdir_r()`, это вызовет предупреждения при компиляции/линковке.

---

## 5. Информационные замечания

### 5.1. Удалённые 32-bit платформы

FreeBSD 15.0 прекратил поддержку i386, armv6 и 32-bit powerpc как самостоятельных
платформ. `crate` собирается на 64-bit платформах — это не затрагивает проект.

### 5.2. Новый jail inotify

FreeBSD 15.0 добавил нативную поддержку `inotify(2)` (Linux-совместимую). Это может
быть полезно для будущего расширения функциональности `crate` (например, мониторинг
изменений в jail).

### 5.3. mac_do(4) для jail'ов

`mac_do(4)` стал production-ready в FreeBSD 15.0 и поддерживает изменение правил
внутри jail'ов через `security.mac.do.rules`. Это может быть полезно для управления
привилегиями внутри контейнеров.

### 5.4. Service Jails — новый тип jail'ов

FreeBSD 15.0 вводит Service Jails — новый тип jail'ов с `path=/` (общая файловая система
с хостом), настраиваемый через одну-две строки в `/etc/rc.conf` (`<service>_svcj=YES`).
Это упрощённая альтернатива для изоляции системных сервисов, не конкурирующая напрямую
с `crate`, но показывающая направление развития jail-экосистемы FreeBSD.

### 5.5. OCI-совместимые контейнеры

FreeBSD теперь публикует OCI-совместимые контейнерные образы. Это конкурирующий
подход к контейнеризации, который может повлиять на стратегическое развитие проекта.

### 5.6. pf(4) поддерживает OpenBSD NAT синтаксис

`pf(4)` теперь поддерживает OpenBSD-style NAT синтаксис. Это не затрагивает `crate`
(который использует `ipfw`), но может быть рассмотрено как альтернатива.

---

## 6. Сводная таблица

| Компонент | Файл(ы) | Совместим? | Приоритет |
|-----------|---------|------------|-----------|
| base.txz URL (FTP) | `locs.cpp:15-17` | НЕТ | CRITICAL |
| ipfw бинарная совм. | `run.cpp`, `create.cpp` | ЧАСТИЧНО | CRITICAL |
| epair checksum bug | `run.cpp:230-248` | ЧАСТИЧНО | CRITICAL |
| jail_setv() API | `run.cpp:158-169` | ДА (deprecated-подход) | HIGH |
| sys/jail.h C++ | `run.cpp:21-23` | ДА (workaround) | HIGH |
| setgroups/getgroups | `run.cpp:364-367` | ТРЕБУЕТ ТЕСТА | HIGH |
| _WITH_GETLINE | `util.cpp:20` | ДА (мёртвый код) | MEDIUM |
| Clang 19 сборка | `Makefile` | ТРЕБУЕТ ТЕСТА | MEDIUM |
| Bridge поведение | `run.cpp:230-248` | ДА (epair OK) | MEDIUM |
| VNET sysctl | `run.cpp:109-115` | ДА | MEDIUM |
| nmount() | `mount.cpp:28-59` | ДА | LOW |
| O_EXLOCK | `ctx.cpp:34` | ДА | LOW |
| sysctlbyname() | `util.cpp:151-170` | ДА | LOW |
| kldload() | `util.cpp:172-174` | ДА | LOW |
| chflags() | `util.cpp:331-353` | ДА | LOW |
| fdclose() | `util.cpp:276` | ДА | LOW |
| nullfs/devfs | `mount.cpp`, `run.cpp` | ДА | LOW |
| epair интерфейсы | `run.cpp:230-232` | ДА | LOW |
| pkg менеджер | `create.cpp:69-114` | ДА | LOW |
| pw/service команды | `run.cpp:356-399` | ДА | LOW |
| rc.conf система | `run.cpp:250-255` | ДА | LOW |

---

## 7. Рекомендуемый план действий

1. **Немедленно:**
   - Заменить FTP URL в `locs.cpp` на HTTPS (`download.freebsd.org`)
   - Добавить отключение checksum offload на epair: `ifconfig epairXa -txcsum -txcsum6`
   - Выполнить тестовую сборку с Clang 19.1.7 на FreeBSD 15.0

2. **Краткосрочно:**
   - Добавить проверку версии FreeBSD при запуске контейнеров
   - Протестировать ipfw NAT в контексте jail'ов FreeBSD 15.0
   - Проверить именование epair-интерфейсов при переносе в jail (vnet0.X vs epairXb)
   - Проверить создание пользователей/групп через `pw` внутри jail

3. **Среднесрочно:**
   - Мигрировать на jail descriptor API (jail_set/jail_get через fd)
   - Добавить поддержку pkgbase как альтернативу base.txz
   - Удалить `_WITH_GETLINE` (или оставить с условной компиляцией)

4. **Долгосрочно:**
   - Подготовиться к полному отказу от distribution sets в FreeBSD 16
   - Рассмотреть OCI-совместимость формата контейнеров

---

## 8. Phase 6: Code Cleanup & Forward-Looking Features (2026-02-26)

Все критические проблемы из Phase 5 были решены. Phase 6 фокусируется на устранении
технического долга (все TODO/FIXME/XXX в коде) и подготовке к FreeBSD 16.

### 8.1. §17: pkgbase support — **РЕАЛИЗОВАНО**

- **Файлы:** `args.h`, `args.cpp`, `create.cpp`
- `--use-pkgbase` флаг для `crate create`
- Bootstrapping jail root через `pkg -r <jailpath> install FreeBSD-runtime` и т.д.
- Записывает `+CRATE.BOOTSTRAP` (pkgbase|base.txz) в контейнер
- Подготовка к FreeBSD 16, где base.txz будет заменён на pkgbase

### 8.2. §18: Dynamic ipfw rule allocation — **РЕАЛИЗОВАНО**

- **Файлы:** `ctx.h`, `ctx.cpp`, `run.cpp`
- `FwSlots` класс: file-based allocator уникальных номеров правил
- Каждый crate получает свой слот, исключая конфликты правил
- Garbage collection удаляет мёртвые PID при аллокации
- Заменяет hardcoded bases (19000/59000) на динамические ranges (10000-29999, 50000-64999)

### 8.3. §19: IP address space documentation & overflow detection — **РЕАЛИЗОВАНО**

- **Файл:** `run.cpp`
- Документация алгоритма аллокации IP в 10.0.0.0/8
- Overflow detection: ERR при epairNum > 2^24
- Bitwise ops вместо деления для clarity

### 8.4. §20: Jail directory permission check — **РЕАЛИЗОВАНО**

- **Файл:** `misc.cpp`
- Проверяет владельца (uid 0) и права (0700) при создании jail directory
- Автоматически исправляет permissions при несоответствии

### 8.5. §21: Exception handling cleanup — **РЕАЛИЗОВАНО**

- **Файл:** `main.cpp`
- Заменены FIXME/XXX маркеры на чистые "internal error:" сообщения

### 8.6. §22: GL GPU vendor detection — **РЕАЛИЗОВАНО**

- **Файл:** `spec.cpp`
- Автоопределение GPU вендора через `pciconf -l`
- NVIDIA (0x10de) → nvidia-driver
- AMD (0x1002) / Intel (0x8086) → drm-kmod
- Fallback: nvidia-driver (legacy)

### Статус TODO/FIXME/XXX

После Phase 6 в кодовой базе **не осталось** маркеров TODO, FIXME или XXX.

---

## Источники

- [FreeBSD 15.0-RELEASE Release Notes](https://www.freebsd.org/releases/15.0R/relnotes/)
- [FreeBSD 15.0-RELEASE Announcement](https://www.freebsd.org/releases/15.0R/announce/)
- [FreeBSD 15 — The Register](https://www.theregister.com/2025/12/05/freebsd_15/)
- [FreeBSD 15.0 Updates — vermaden](https://vermaden.wordpress.com/2025/11/30/valuable-freebsd-15-0-release-updates/)
- [Jails and upgrades to 15.0 — Forums](https://forums.freebsd.org/threads/jails-and-upgrades-to-15-0.100558/)
- [VNET jail in FreeBSD 15 — Forums](https://forums.freebsd.org/threads/problem-about-vnet-jail-in-freebsd15.101193/)
- [FreeBSD Foundation: Fixes and Features](https://freebsdfoundation.org/our-work/journal/browser-based-edition/freebsd-15-0/freebsd-15-0-fixes-and-features/)
- [Brave New PKGBASE World — vermaden](https://vermaden.wordpress.com/2025/10/20/brave-new-pkgbase-world/)
- [Epair checksum/naming issues in 15.0 — Forums](https://forums.freebsd.org/threads/epair0-behaves-like-schrodingers-cat-and-is-not-working-anymore-after-upgrading-to-15-0.101110/)
- [VNET jail networking issues in 15.0 — Forums](https://forums.freebsd.org/threads/no-access-to-external-network-from-vnet-jails-in-15-0-release.100669/)
- [ipfw_ctl3 invalid option after upgrade — Forums](https://forums.freebsd.org/threads/upgrading-from-14-3-p6-to-15-0-ipfw_ctl3-invalid-option-98v0-97v0.100606/)
- [FreeBSD 15 Bridges, VLANs and Jails — Forums](https://forums.freebsd.org/threads/freebsd-15-bridges-vlans-and-jails-nice.101719/)
- [setgroups/getgroups changes — FreeBSD Status Report](https://www.freebsd.org/status/report-2025-04-2025-06/group-changes/)
- [MNT_IGNORE fix for devfs/nullfs](https://www.mail-archive.com/dev-commits-src-all@freebsd.org/msg53388.html)
