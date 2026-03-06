# Аналіз сумісності проєкту `crate` з FreeBSD 15.0

**Дата аналізу:** 2026-02-19
**Версія FreeBSD:** 15.0-RELEASE (випущена 2 грудня 2025)
**Проєкт:** crate — засіб контейнеризації для FreeBSD (C++17)

---

## Загальна оцінка

**Рівень сумісності: СЕРЕДНІЙ (потрібні зміни)**

Проєкт `crate` є нативним FreeBSD-застосунком, написаним на C++17, і загалом
добре сумісний з FreeBSD 15.0, однак є низка проблем різної критичності,
що потребують уваги.

---

## 1. Критичні проблеми (CRITICAL)

### 1.1. URL завантаження base.txz — FTP deprecated

**Файл:** `locs.cpp:15-17`

```cpp
const std::string baseArchiveUrl = STRg("ftp://ftp1.freebsd.org/pub/FreeBSD/snapshots/"
                                        << Util::getSysctlString("hw.machine") << "/"
                                        << Util::getSysctlString("kern.osrelease")
                                        << "/base.txz");
```

**Проблема:** Проєкт використовує `ftp://ftp1.freebsd.org/pub/FreeBSD/snapshots/` для завантаження
base.txz. У FreeBSD 15.0:

- `ftpd(8)` вилучено з базової системи
- Канонічний URL змінено на `https://download.freebsd.org/`
- FTP-сервери FreeBSD поступово виводяться з експлуатації

Команда `fetch` (використовується у `create.cpp:282`) підтримує HTTPS, але сам URL вказує
на потенційно недоступний FTP-сервер.

Крім того, з переходом на **pkgbase** у FreeBSD 15.0 структура дистрибутивних наборів
змінюється. У FreeBSD 16 заплановано повну відмову від distribution sets (base.txz, kernel.txz)
на користь pkgbase. Для створення jail'ів через pkgbase використовується:
`pkg -r /jails/myjail install FreeBSD-set-base`.

**Дія:** Замінити URL на `https://download.freebsd.org/releases/` або
`https://download.freebsd.org/snapshots/`, а в перспективі — реалізувати підтримку pkgbase.

### 1.2. Бінарна несумісність ipfw у jail'ах

**Файли:** `run.cpp:264-338`, `create.cpp:212-216`

**Проблема:** З ядра FreeBSD 15.0 вилучено код сумісності для бінарних файлів `ipfw`
з FreeBSD 7/8 (коміт `4a77657cbc01`). При запуску контейнерів, створених на базі
FreeBSD 14.x, на хості з FreeBSD 15.0 `ipfw` всередині jail'у не працюватиме:

```
ipfw: setsockopt(IP_FW_XDEL): Invalid argument
ipfw: getsockopt(IP_FW_XADD): Invalid argument
```

Це безпосередньо впливає на мережевий стек `crate`, оскільки проєкт активно використовує `ipfw`
для NAT та фільтрації трафіку всередині та ззовні jail'у.

**Дія:** Контейнери, створені на FreeBSD <15.0, необхідно перестворити з base.txz
від FreeBSD 15.0. Рекомендовано додати перевірку версії при запуску.

### 1.3. Помилка TCP checksum offload в epair-інтерфейсах

**Файл:** `run.cpp:230-248`

```cpp
std::string epipeIfaceA = Util::stripTrailingSpace(
    Util::runCommandGetOutput("ifconfig epair create", "create the jail epipe"));
std::string epipeIfaceB = STR(epipeIfaceA.substr(0, epipeIfaceA.size()-1) << "b");
```

**Проблема:** Після оновлення до FreeBSD 15.0 користувачі масово повідомляють про проблеми
з мережевим доступом із VNET jail'ів через epair-інтерфейси
([Forum](https://forums.freebsd.org/threads/no-access-to-external-network-from-vnet-jails-in-15-0-release.100669/)).

Причина: epair підтримує `TXCSUM`/`TXCSUM6` (checksum offloading) та пересилає обчислення
контрольних сум на фізичний інтерфейс. Якщо пакети не залишають хост (jail->host або
jail->jail), контрольна сума ніколи не обчислюється, і пакети відкидаються.

**Дія:** Після створення epair-інтерфейсів додати:
```
ifconfig epairXa -txcsum -txcsum6
ifconfig epairXb -txcsum -txcsum6
```

Також помічено проблеми з іменуванням інтерфейсів при перенесенні в jail — можлива
поява `vnet0.X` замість очікуваного `epairXb`
([Forum](https://forums.freebsd.org/threads/epair0-behaves-like-schrodingers-cat-and-is-not-working-anymore-after-upgrading-to-15-0.101110/)).
Потрібне тестування парсингу імен інтерфейсів.

---

## 2. Високий пріоритет (HIGH)

### 2.1. Jail API — нові файлові дескриптори

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

**Зміни у FreeBSD 15.0:**
- Додано нові syscall'и: `jail_set(2)`, `jail_get(2)`, `jail_attach_jd(2)`,
  `jail_remove_jd(2)` для роботи через файлові дескриптори
- Усунуто race conditions, пов'язані з використанням jail ID
- Додано параметри `meta` та `env` для метаданих і змінних оточення
- Підтримка `zfs.dataset` для приєднання ZFS-датасетів

**Статус:** Наявний код із `jail_setv()` та `jail_remove()` продовжує працювати
(зворотна сумісність збережена), але рекомендовано міграцію на новий API для
усунення race conditions.

**Дія:** Розглянути міграцію на jail descriptor API для надійності.

### 2.2. `sys/jail.h` не є C++-safe

**Файл:** `run.cpp:21-23`

```cpp
extern "C" { // sys/jail.h isn't C++-safe: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=238928
#include <sys/jail.h>
}
```

**Статус:** За наявними даними, помилка #238928 досі не виправлена у FreeBSD 15.0.
Обгортка `extern "C"` залишається необхідною. Потрібна перевірка під час збірки.

### 2.3. Зміна поведінки `setgroups(2)` / `getgroups(2)`

**Файли:** `run.cpp:364-367` (використання `pw useradd`, `pw groupadd`, `pw usermod`)

**Зміна у FreeBSD 15.0:** `setgroups(2)`, `getgroups(2)` та `initgroups(3)` змінено —
effective group ID більше не включається до масиву. Це може вплинути на налаштування
користувачів усередині jail'у через `pw`.

**Дія:** Протестувати створення користувачів і груп усередині jail'у з FreeBSD 15.0
base, переконатися що належність до груп (wheel, videoops) коректна.

---

## 3. Середній пріоритет (MEDIUM)

### 3.1. `_WITH_GETLINE` — ймовірно, більше не потрібен

**Файл:** `util.cpp:20`

```cpp
#define _WITH_GETLINE // it breaks on 11.3 w/out this, but the manpage getline(3) doesn't mention _WITH_GETLINE
```

**Зміна:** У FreeBSD 15.0 `getline()` експортується за замовчуванням без необхідності
визначення `_WITH_GETLINE` або `_POSIX_C_SOURCE`. Визначення `_WITH_GETLINE` не спричиняє
помилки, але є мертвим кодом.

**Дія:** Можна безпечно вилучити `#define _WITH_GETLINE`. Якщо потрібна зворотна
сумісність із FreeBSD <15.0, можна залишити з коментарем.

### 3.2. LLVM/Clang оновлено до версії 19.1.7

**Файл:** `Makefile:10`

```makefile
CXXFLAGS+= -Wall -std=c++17
```

**Зміна:** FreeBSD 15.0 постачається з Clang 19.1.7 (у FreeBSD 14.0 був Clang 16.0.6).
Clang 19 запроваджує нові попередження та посилює перевірки.

**Потенційні проблеми:**
- Нові попередження при `-Wall` (особливо для C-style casts, неявних перетворень)
- Суворіша перевірка відповідності C++17
- GoogleTest (якщо використовується) тепер вимагає щонайменше C++14

**Дія:** Виконати тестову збірку та перевірити нові попередження/помилки.

### 3.3. Зміна поведінки bridge-інтерфейсів

**Файл:** `run.cpp:230-248` (epair-інтерфейси)

**Зміна:** У FreeBSD 15.0 bridge почав дозволяти IP лише на самому bridge, а не
на member-інтерфейсах. Це може вплинути на мережеву конфігурацію VNET jail'ів, якщо
використовуються bridge-інтерфейси.

**Статус:** `crate` використовує epair безпосередньо (без bridge), тому ця зміна
найімовірніше не зачіпає проєкт безпосередньо, але потребує уваги при розширенні
мережевих можливостей.

### 3.4. VNET sysctl як loader tunables

**Файл:** `run.cpp:109-115`

```cpp
if (Util::getSysctlInt("kern.features.vimage") == 0)
    ERR(...)
if (Util::getSysctlInt("net.inet.ip.forwarding") == 0)
    Util::setSysctlInt("net.inet.ip.forwarding", 1);
```

**Зміна:** VNET sysctl змінні тепер можуть бути loader tunables (розширення
`CTLFLAG_TUN`). Це означає, що `net.inet.ip.forwarding` та подібні змінні можуть
бути встановлені через loader.conf ще до завантаження ядра.

**Дія:** Функціональність не порушена, але варто оновити документацію.

---

## 4. Низький пріоритет (LOW)

### 4.1. Сумісність `nmount()` — OK (покращено)

**Файл:** `mount.cpp:28-59`

`nmount()` — стабільний FreeBSD syscall. У FreeBSD 15.0 виправлено обробку прапорця
`MNT_IGNORE` для devfs, fdescfs та nullfs — прапорець тепер коректно зберігається через
`nmount(2)`, що зменшує шум від `df(1)` та `mount(8)` при контейнерних навантаженнях.
API та сигнатура виклику не змінилися.

### 4.2. `O_EXLOCK` — OK

**Файл:** `ctx.cpp:34`

```cpp
ctx->fd = ::open(file().c_str(), O_RDWR|O_CREAT|O_EXLOCK, 0600);
```

`O_EXLOCK` — стандартний BSD-прапорець, змін не виявлено. Працює коректно.

### 4.3. `sysctlbyname()` — OK

**Файли:** `util.cpp:151-170`

Syscall `sysctlbyname()` не зазнав змін. Утиліта `sysctl(8)` отримала
додаткові функції (jail attachment, фільтрація vnet/prison змінних), але API
для програмного доступу стабільний.

### 4.4. `kldload()` — OK

**Файл:** `util.cpp:172-174`

API `kldload()` стабільний, змін не виявлено.

### 4.5. `chflags()` — OK

**Файл:** `util.cpp:331-353`

Системний виклик `chflags()` стабільний, змін не виявлено.

### 4.6. `fdclose()` — OK

**Файл:** `util.cpp:276`

```cpp
if (::fdclose(file, nullptr) != 0)
```

`fdclose()` (з'явився у FreeBSD 11.0) як і раніше доступний у FreeBSD 15.0.

### 4.7. `readdir_r(3)` — deprecated

Проєкт не використовує `readdir_r()` безпосередньо (натомість використовується
`std::filesystem::directory_iterator`), але якщо будь-яка залежність використовує
`readdir_r()`, це спричинить попередження під час компіляції/лінкування.

---

## 5. Інформаційні зауваження

### 5.1. Вилучені 32-bit платформи

FreeBSD 15.0 припинив підтримку i386, armv6 та 32-bit powerpc як самостійних
платформ. `crate` збирається на 64-bit платформах — це не зачіпає проєкт.

### 5.2. Новий jail inotify

FreeBSD 15.0 додав нативну підтримку `inotify(2)` (Linux-сумісну). Це може
бути корисним для майбутнього розширення функціональності `crate` (наприклад, моніторинг
змін у jail).

### 5.3. mac_do(4) для jail'ів

`mac_do(4)` став production-ready у FreeBSD 15.0 та підтримує зміну правил
усередині jail'ів через `security.mac.do.rules`. Це може бути корисним для керування
привілеями всередині контейнерів.

### 5.4. Service Jails — новий тип jail'ів

FreeBSD 15.0 запроваджує Service Jails — новий тип jail'ів з `path=/` (спільна файлова система
з хостом), що налаштовується через один-два рядки в `/etc/rc.conf` (`<service>_svcj=YES`).
Це спрощена альтернатива для ізоляції системних сервісів, що не конкурує безпосередньо
з `crate`, але показує напрямок розвитку jail-екосистеми FreeBSD.

### 5.5. OCI-сумісні контейнери

FreeBSD тепер публікує OCI-сумісні контейнерні образи. Це конкуруючий
підхід до контейнеризації, який може вплинути на стратегічний розвиток проєкту.

### 5.6. pf(4) підтримує OpenBSD NAT синтаксис

`pf(4)` тепер підтримує OpenBSD-style NAT синтаксис. Це не зачіпає `crate`
(який використовує `ipfw`), але може бути розглянуто як альтернатива.

---

## 6. Зведена таблиця

| Компонент | Файл(и) | Сумісний? | Пріоритет |
|-----------|---------|-----------|-----------|
| base.txz URL (FTP) | `locs.cpp:15-17` | НІ | CRITICAL |
| ipfw бінарна суміс. | `run.cpp`, `create.cpp` | ЧАСТКОВО | CRITICAL |
| epair checksum bug | `run.cpp:230-248` | ЧАСТКОВО | CRITICAL |
| jail_setv() API | `run.cpp:158-169` | ТАК (deprecated-підхід) | HIGH |
| sys/jail.h C++ | `run.cpp:21-23` | ТАК (workaround) | HIGH |
| setgroups/getgroups | `run.cpp:364-367` | ПОТРЕБУЄ ТЕСТУВАННЯ | HIGH |
| _WITH_GETLINE | `util.cpp:20` | ТАК (мертвий код) | MEDIUM |
| Clang 19 збірка | `Makefile` | ПОТРЕБУЄ ТЕСТУВАННЯ | MEDIUM |
| Bridge поведінка | `run.cpp:230-248` | ТАК (epair OK) | MEDIUM |
| VNET sysctl | `run.cpp:109-115` | ТАК | MEDIUM |
| nmount() | `mount.cpp:28-59` | ТАК | LOW |
| O_EXLOCK | `ctx.cpp:34` | ТАК | LOW |
| sysctlbyname() | `util.cpp:151-170` | ТАК | LOW |
| kldload() | `util.cpp:172-174` | ТАК | LOW |
| chflags() | `util.cpp:331-353` | ТАК | LOW |
| fdclose() | `util.cpp:276` | ТАК | LOW |
| nullfs/devfs | `mount.cpp`, `run.cpp` | ТАК | LOW |
| epair інтерфейси | `run.cpp:230-232` | ТАК | LOW |
| pkg менеджер | `create.cpp:69-114` | ТАК | LOW |
| pw/service команди | `run.cpp:356-399` | ТАК | LOW |
| rc.conf система | `run.cpp:250-255` | ТАК | LOW |

---

## 7. Рекомендований план дій

1. **Негайно:**
   - Замінити FTP URL у `locs.cpp` на HTTPS (`download.freebsd.org`)
   - Додати вимкнення checksum offload на epair: `ifconfig epairXa -txcsum -txcsum6`
   - Виконати тестову збірку з Clang 19.1.7 на FreeBSD 15.0

2. **Короткостроково:**
   - Додати перевірку версії FreeBSD при запуску контейнерів
   - Протестувати ipfw NAT у контексті jail'ів FreeBSD 15.0
   - Перевірити іменування epair-інтерфейсів при перенесенні в jail (vnet0.X vs epairXb)
   - Перевірити створення користувачів/груп через `pw` усередині jail

3. **Середньостроково:**
   - Мігрувати на jail descriptor API (jail_set/jail_get через fd)
   - Додати підтримку pkgbase як альтернативу base.txz
   - Вилучити `_WITH_GETLINE` (або залишити з умовною компіляцією)

4. **Довгостроково:**
   - Підготуватися до повної відмови від distribution sets у FreeBSD 16
   - Розглянути OCI-сумісність формату контейнерів

---

## 8. Phase 6: Code Cleanup & Forward-Looking Features (2026-02-26)

Усі критичні проблеми з Phase 5 було вирішено. Phase 6 зосереджується на усуненні
технічного боргу (всі маркери TODO/FIXME/XXX у коді) та підготовці до FreeBSD 16.

### 8.1. §17: pkgbase support — **РЕАЛІЗОВАНО**

- **Файли:** `args.h`, `args.cpp`, `create.cpp`
- `--use-pkgbase` прапорець для `crate create`
- Bootstrapping jail root через `pkg -r <jailpath> install FreeBSD-runtime` тощо
- Записує `+CRATE.BOOTSTRAP` (pkgbase|base.txz) до контейнера
- Підготовка до FreeBSD 16, де base.txz буде замінено на pkgbase

### 8.2. §18: Dynamic ipfw rule allocation — **РЕАЛІЗОВАНО**

- **Файли:** `ctx.h`, `ctx.cpp`, `run.cpp`
- `FwSlots` клас: file-based allocator унікальних номерів правил
- Кожен crate отримує власний слот, що унеможливлює конфлікти правил
- Garbage collection вилучає мертві PID під час алокації
- Замінює hardcoded bases (19000/59000) на динамічні ranges (10000-29999, 50000-64999)

### 8.3. §19: IP address space documentation & overflow detection — **РЕАЛІЗОВАНО**

- **Файл:** `run.cpp`
- Документація алгоритму алокації IP у 10.0.0.0/8
- Overflow detection: ERR при epairNum > 2^24
- Bitwise ops замість ділення для зрозумілості

### 8.4. §20: Jail directory permission check — **РЕАЛІЗОВАНО**

- **Файл:** `misc.cpp`
- Перевіряє власника (uid 0) та права (0700) при створенні jail directory
- Автоматично виправляє permissions при невідповідності

### 8.5. §21: Exception handling cleanup — **РЕАЛІЗОВАНО**

- **Файл:** `main.cpp`
- Маркери FIXME/XXX замінено на чисті повідомлення "internal error:"

### 8.6. §22: GL GPU vendor detection — **РЕАЛІЗОВАНО**

- **Файл:** `spec.cpp`
- Автовизначення GPU вендора через `pciconf -l`
- NVIDIA (0x10de) → nvidia-driver
- AMD (0x1002) / Intel (0x8086) → drm-kmod
- Fallback: nvidia-driver (legacy)

### Статус TODO/FIXME/XXX

Після Phase 6 у кодовій базі **не залишилося** маркерів TODO, FIXME або XXX.

---

## Джерела

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
