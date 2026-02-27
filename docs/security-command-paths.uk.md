# Безпека: шляхи до зовнішніх команд

## Чому абсолютні шляхи?

Crate — **setuid root** бінарний файл. Коли setuid-програма виконує зовнішні команди
за іменем (наприклад, `zfs`, `ipfw`), оболонка шукає їх за змінною оточення `PATH`.
Зловмисник може встановити `PATH=/tmp/evil:$PATH` і розмістити зловмисний скрипт
з назвою `zfs` у `/tmp/evil/` — він буде виконаний від імені root.

Це [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html).

## Як crate вирішує цю проблему

Crate використовує трирівневий захист від атак через ненадійний шлях пошуку:

### 1. Централізовані визначення шляхів (`pathnames.h`)

Всі шляхи до зовнішніх команд визначені як compile-time константи у `pathnames.h`:

```cpp
#define CRATE_PATH_ZFS        "/sbin/zfs"
#define CRATE_PATH_IPFW       "/sbin/ipfw"
#define CRATE_PATH_IFCONFIG   "/sbin/ifconfig"
// ... ~30 команд загалом
```

Це відповідає тому ж патерну, що й системний `<paths.h>` FreeBSD, який визначає
`_PATH_IFCONFIG`, `_PATH_MOUNT` тощо для утиліт базової системи.

### 2. Очищення оточення (`main.cpp`)

При запуску, перед будь-якими іншими операціями, crate:

1. Зберігає `TERM`, `DISPLAY`, `WAYLAND_DISPLAY`, `LANG`, `XAUTHORITY`
2. Очищує все оточення (`environ = empty_env`)
3. Встановлює безпечний `PATH` з `_PATH_DEFPATH` (`/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin`)
4. Відновлює лише збережені безпечні змінні

Це запобігає успадкуванню `LD_PRELOAD`, `LD_LIBRARY_PATH` та інших небезпечних
змінних дочірніми процесами.

### 3. `execv` замість `execvp`

Все виконання команд використовує `execv()` (який вимагає абсолютний шлях) замість
`execvp()` (який шукає по `PATH`). Аналогічно, `execl()` використовується замість `execlp()`.

## Перевизначення шляхів до команд

Для нестандартних інсталяцій FreeBSD, де команди знаходяться в інших місцях,
шляхи можна перевизначити під час **компіляції** через Makefile:

```sh
# Приклад: ZFS встановлений з портів замість базової системи
make CXXFLAGS+='-DCRATE_PATH_ZFS="/usr/local/sbin/zfs"'

# Кілька перевизначень
make CXXFLAGS+='-DCRATE_PATH_ZFS="/usr/local/sbin/zfs" -DCRATE_PATH_XEPHYR="/usr/local/bin/Xephyr"'
```

Захисти `#ifndef` у `pathnames.h` дозволяють перевизначити будь-який шлях без
редагування header-файлу.

### Чому не runtime конфігураційний файл?

Для setuid-бінарника runtime конфігураційний файл (`paths.conf`) був би додатковим
вектором атаки — якщо зловмисник зможе модифікувати конфіг, він зможе перенаправити
виконання команд. CWE-426 явно попереджає: *"Do not allow these settings to be modified
by an external party."*

Compile-time конфігурація не має runtime поверхні атаки.

## Порівняння з іншими інструментами FreeBSD

| Інструмент | Підхід | setuid? |
|------------|--------|---------|
| **FreeBSD `<paths.h>`** | `#define _PATH_*` compile-time константи | Так (login, su) |
| **sudo** | `secure_path` у конфігу sudoers | Ні (використовує suid helper) |
| **iocage** | Хардкод безпечного PATH + абсолютні шляхи для критичних команд | Ні |
| **cbsd** | `cmdboot` автогенерує `cmd.subr` через `which` при ініціалізації | Ні |
| **BastilleBSD** | PATH-relative bare names | Ні |
| **crate** | `pathnames.h` compile-time + очищення env + `execv` | **Так** |

## Шляхи за замовчуванням

Повний список див. у `pathnames.h`. Всі значення за замовчуванням відповідають
стандартним розташуванням базової системи FreeBSD (`/sbin/`, `/usr/sbin/`, `/usr/bin/`,
`/bin/`). Команди з портів/пакетів мають шляхи `/usr/local/bin/` або `/usr/local/sbin/`.

### Команди базової системи FreeBSD

| Визначення | Шлях за замовчуванням | Призначення |
|-----------|----------------------|-------------|
| `CRATE_PATH_ZFS` | `/sbin/zfs` | ZFS snapshots, clones, datasets, шифрування |
| `CRATE_PATH_IPFW` | `/sbin/ipfw` | Правила файрволу для NAT та мережі jail |
| `CRATE_PATH_PFCTL` | `/sbin/pfctl` | pf anchor правила (альтернатива ipfw) |
| `CRATE_PATH_IFCONFIG` | `/sbin/ifconfig` | Налаштування epair інтерфейсів |
| `CRATE_PATH_ROUTE` | `/sbin/route` | Маршрут за замовчуванням у jail |
| `CRATE_PATH_DEVFS` | `/sbin/devfs` | Правила файлової системи пристроїв |
| `CRATE_PATH_JEXEC` | `/usr/sbin/jexec` | Виконання команд всередині jail |
| `CRATE_PATH_PKG` | `/usr/sbin/pkg` | Встановлення пакетів під час створення crate |
| `CRATE_PATH_RCTL` | `/usr/bin/rctl` | Ліміти ресурсів (RCTL) |
| `CRATE_PATH_UGIDFW` | `/usr/sbin/ugidfw` | MAC bsdextended правила |

### Команди з портів/пакетів

| Визначення | Шлях за замовчуванням | Призначення |
|-----------|----------------------|-------------|
| `CRATE_PATH_XEPHYR` | `/usr/local/bin/Xephyr` | Вкладений X11 сервер для ізоляції GUI |
| `CRATE_PATH_SOCAT` | `/usr/local/bin/socat` | Проксіювання Unix-сокетів |
| `CRATE_PATH_UNBOUND` | `/usr/local/sbin/unbound` | Per-jail DNS-фільтрація |
