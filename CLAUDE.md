# CLAUDE.md — інструкції для сесій Claude Code у цьому репозиторії

crate — контейнеризатор для FreeBSD: пакує застосунок у `.crate` і запускає
його в окремому jail (VNET, ZFS, pf/ipfw). C++17, BSD-3-Clause. Чотири
програми: `crate` (CLI), `crated` (демон: REST API, control-сокети, privops),
`crate-snmpd` (AgentX), `crate-hub` (агрегатор вузлів і дашборд).

## Перше, що зробити в новому клоні

Linux (так ганяє CI; FreeBSD-специфічний код тут не збирається, лише юніт-тести):

```sh
sudo apt-get install -y g++ make libatf-dev kyua
make -j"$(nproc)" test-unit \
  TEST_CXXWARN="-Wall -Wextra -Wno-missing-field-initializers -Werror" \
  KYUA_FLAGS="-v parallelism=$(nproc)"
```

FreeBSD (повна збірка): `pkg install pkgconf yaml-cpp rang gmake cpp-httplib sqlite3 atf`,
далі `make` / `make all-daemon` / `make all-snmpd` / `make all-hub` і `make test`.

## Мова спілкування

Відповідати користувачу **українською**. Код, коментарі в коді, коміти,
CHANGELOG — англійською. README двомовний (`README.md` + `README_UK.md`),
частина `docs/` теж має пару `X.uk.md` — змінюючи такий документ, міняти обидва.
Коментарі в `.github/workflows/freebsd-build*.yml` історично українською —
дописувати там тією ж мовою, що й навколо.

## Збірка і перевірки

- `make check-version` — `VERSION`, `PORTVERSION` у `port/Makefile` і секція
  `## [X.Y.Z]` у `CHANGELOG.md` мусять збігатися; `lib/version.h`
  генерується з `VERSION` (руками не писати, у `cli/args.cpp` не хардкодити).
- `make check-kyuafile` — кожен бінарник з `UNIT_TESTS` у `Makefile` має бути
  в `tests/unit/Kyuafile` (інакше kyua мовчки його не запускає). Новий
  тест = рядок у `UNIT_TESTS` + рядок у `tests/unit/Kyuafile`.
- За замовчуванням `-Wall -Wextra` без `-Werror`; Linux CI додає `-Werror`
  до тестів і окремо ганяє їх під ASan + UBSan.
- `tests/functional/` — лише FreeBSD (потрібен jail), у Linux не запускаються.

CI (`.github/workflows/`):
- `linux-unit.yml` — юніт-сюїта і ASan+UBSan, на кожен push і на кожен PR у `main`.
- `freebsd-build-lite.yml` — компіляція й лінк усіх програм + юніт-сюїта у VM
  FreeBSD, лише на push (docs/TODO/CHANGELOG/man — у `paths-ignore`).
- `freebsd-build.yml` — повна, з функціональними тестами; **лише вручну**
  (GitHub-hosted QEMU для неї непридатний), тож функціональні тести зараз
  нічого не гейтять.
- `release.yml` — на тег `v*`: сторінка релізу з `CHANGELOG.md` і бінарники
  з VM FreeBSD.

## Архітектура (коротко)

- `lib/` → `libcrate.a`: уся логіка CLI і спільний код демонів (spec, run,
  мережа, ZFS, GUI, backup/replicate, профілі, privops-клієнт, реєстри).
- `cli/` — `crate(1)`: розбір аргументів і диспетчер команд.
- `daemon/` — `crated`: HTTP API (`routes`, `server`), control-сокети на
  користувача, privops-слухач і обробники, ws-console, метрики.
- `hub/` — `crate-hub`: poller вузлів, sqlite-сховище, API, `hub/web/`.
- `snmpd/` — `crate-snmpd` (AgentX, `CRATE-MIB.txt`).
- `port/` — порт FreeBSD (`Makefile`, `pkg-plist`); `crate.5`, `crated.8`,
  `crate-hub.8`, `crate-snmpd.8` — man-сторінки; `examples/` — специфікації,
  вони ж — набір профілів для `crate run <name>`; `templates/`, `completions/`.
- **Патерн `*_pure`**: логіку, яку можна перевірити без FreeBSD, виносять у
  `foo_pure.{h,cpp}` (без syscall-ів jail/ZFS/pf, без I/O), а `foo.cpp`
  робить I/O. Юніт-тести лінкують лише `*_pure`-об'єкти й ідуть на Linux.
  `lib/spec.cpp` (yaml-cpp) у тести не лінкується — валідацію ключів
  виносити в `SpecPure`.

## Інваріанти — не ламати

- `crate(1)` не setuid (з 1.0.0). Привілейоване робить `crated` через
  privops-сокет (libnv; `lib/privops_client*`, `daemon/privops_*`);
  рішення — в `lib/privops_authz_pure` (`DenyUnownedJid`, `DenyForeignIface`,
  `DenyUnownedPath`, …) за реєстрами власників jid / інтерфейсів / шляхів:
  користувач чіпає лише своє. Новий privops-верб = валідація форми +
  перевірка власника + тест на authz.
- Шляхи до системних команд — лише з `lib/pathnames.h` (`CRATE_PATH_*`),
  не вписувати руками.
- Одне джерело версії — `VERSION`.
- Коментар до нової поведінки позначає реліз, що її приніс
  (`// 1.1.48: …`) — так влаштований увесь код; тримати цей стиль.

## Коміти, версії, релізи

- Робота — через PR у `main`, мерж **squash**; заголовок —
  `X.Y.Z: <що змінилось> (#N)` або `TODO §N <пріоритет>: … (X.Y.Z) (#N)`.
- **Кожен PR зі зміною коду — нова версія**: `VERSION`, `PORTVERSION` у
  `port/Makefile` і секція `## [X.Y.Z] — дата` у `CHANGELOG.md` (жирний
  абзац-підсумок першим, далі пункти). PR лише з документацією/TODO
  версію не піднімає.
- Тег `vX.Y.Z` ставить користувач; один тег може накривати кілька версій
  CHANGELOG — `release.yml` бере всі секції після попереднього тега.
- Трейлери в кінці повідомлення коміту:
  ```
  Co-Authored-By: Claude <модель> <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_<id>
  ```
  Ніяких ідентифікаторів моделі в коді, коментарях, доках чи описах PR.

## Де відкриті задачі

GitHub Issues у цьому репозиторії **вимкнені**, тож трекер — файли:
- `TODO` — баги й незроблене, з легендою пріоритетів (HIGH / MED / LOW) і
  цитатами `file:line`; розділи нумеровані (`TODO §N`), на них посилаються
  коміти й коментарі в коді.
- `TODO2` — окремий трек bhyve / micro-VM.

Виправили пункт — **прибрати його з TODO** і описати в CHANGELOG під версією;
позначки `[FIXED in …]` у TODO не лишати (у 1.1.69 їх накопичилось 50, і
шапка файлу казала неправду). Що виправлення лишило відкритим — окремим
пунктом із пріоритетом. Якщо Issues колись увімкнуть — перенести туди
відкриті пункти й лишити в TODO лише посилання.
