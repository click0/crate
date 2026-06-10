# Модель довіри та мультитенантна ізоляція

**Аудиторія:** оператори, що запускають crate на спільному хості
(кілька операторів на одній машині), і контрибʼютори, які розширюють
привілейовану поверхню.

**Стосується:** 1.1.15 (rootless-модель + серія per-tenant authz 1.1.12 →
1.1.15 покриває кожен privops-верб з operator-controlled ownership-
сигналом). Про ≤ 0.9.x setuid-модель і міграцію див.
[`rootless-migration.md`](rootless-migration.md).

Цей документ явно фіксує, **де enforce-иться міжтенантна ізоляція, а
де — ні**, щоб розгортання правильно визначали межі довіри, а майбутні
зміни не зламали їх непомітно.

---

## Стисло

Crate має дві площини з двома різними моделями довіри:

1. **Площина привілейованого виконання — privops-поверхня `crated`.**
   Починаючи з 1.0.0 `crate(1)` **більше не setuid** (`Makefile`,
   `-m 0755`); це непривілейований клієнт. Кожну root-операцію
   (створення/знищення jail, ZFS attach, mount, RCTL, налаштування
   інтерфейсів/фаєрволу, сигнали) виконує `crated` (працює від root) на
   запит через **privops** — або `POST /api/v1/privops/<verb>`
   (лише admin), або libnv `AF_UNIX` privops-сокет (gated по групі).
   Ця площина **не арбітрує між операторами.** Будь-хто, хто має доступ
   до privops, має root-еквівалентний контроль над *кожним* jail на
   хості. Це **єдиний домен довіри** — та сама властивість, що мав
   старий setuid `crate(1)`, перенесена в демон.

2. **Площина спостереження / контролю з пулами.** Саме тут
   **enforce-иться потенантна ізоляція**, через pool-ACL + scope токена,
   на точках входу, що несуть ідентичність викликача: виділені
   control-сокети (`getpeereid` gid + pool ACL), віддалені bearer-токени
   (scope + pool ACL) та ws-консоль (bearer + pool ACL). Поверхня:
   `list` / `get` / `stats` / `logs` / `start` / `stop` / `restart` /
   `PATCH resources` / інтерактивна консоль.

**Інваріант:** мультитенантна ізоляція між взаємно недовірливими
операторами живе **лише** на точках входу площини з пулами, що несуть
ідентичність (control-сокет `pools`, токен `pools` + `scope`),
enforce-иться на боці демона на кожен запит і прив'язана до пулу
**цільового** jail. Privops-площина та локальний Unix-сокет-доступ до
головного HTTP API — це єдині домени довіри. Тому розгортання з
ворожою мультитенантністю має видавати недовіреним операторам **лише
pool-scoped control-сокет або bearer-токен** — ніколи доступ до
privops-сокета, ніколи admin-токен і ніколи Unix-сокет головного API.

---

## Що змінилось від 0.7.19 — привілейована площина переїхала

У 0.7.19 єдиним доменом довіри привілейованої площини був setuid-root
бінарник `crate(1)`. Rootless-трек (0.9.0–1.0.0, див.
[`rootless-migration.md`](rootless-migration.md)) виніс кожну
привілейовану операцію з `crate(1)` у privops-поверхню `crated`; 1.0.0
зняв setuid-біт (`Makefile`, коментар біля install-рядка `crate`:
*«setuid bit removed. crate(1) runs as the operator and delegates
privileged operations to crated(8)»*).

Властивість «єдиний домен довіри» **не зникла** — вона переїхала.
Міркувати про ізоляцію на 1.1.15 — це міркувати про те, хто має доступ
до **privops**, а не хто може запустити `crate(1)`.

---

## Площина 1 — privops, привілейоване виконання (єдиний домен довіри)

`crate(1)` встановлюється `-m 0755` (`Makefile`; setuid знято в 1.0.0).
`crated` працює від root (rc.d) і є єдиним привілейованим бінарником.
Він виконує root-операції лише у відповідь на закритий набір **privops-
вербів** (`create_jail`, `destroy_jail`, `attach_zfs`, `set_rctl`,
`configure_iface`, `add_pf_rule`, `signal_jail`, `apply_devfs_ruleset`,
… — `lib/privops_pure.h`). До нього ведуть два транспорти:

- **HTTP — `POST /api/v1/privops/<verb>`.** Gated **лише admin**:
  `isAuthorized(req, config, "admin")` (`daemon/routes.cpp:1007`).
  Коментар обробника прямо фіксує задум — *«Privops touch host-wide
  state … so per-container scope from the F2 surface doesn't apply»*
  (`daemon/routes.cpp:997-999`). На цьому шляху uid оператора лишається
  `0` (cpp-httplib не віддає fd зʼєднання для `getpeereid`), тож
  per-user audit — no-op (`daemon/routes.cpp:1013-1019`).
- **libnv `AF_UNIX` сокет (0.9.14).** Gated по групі: лістенер робить
  `chmod` сокета до його mode і `chown` на `root:<group>`
  (`daemon/privops_listener.cpp:179,188`; типовий mode `0660`,
  `daemon/config.h:117-119`). `getpeereid(2)` дістає uid піра
  (`daemon/privops_listener.cpp:90`) і живить як гачок per-user audit /
  namespacing, **так і** authorize-before-dispatch гейт нижче.

Диспетчеризація вербів — це `parse → validate → handle` (`dispatchPrivOp`
/ `dispatchPrivOpFromMap`, `daemon/privops_handlers.cpp`). Авторизація
різна за транспортом:

- **HTTP:** перевірки за ресурсом немає — лише `admin`, host-wide за
  задумом (`daemon/routes.cpp:997-999`).
- **libnv (реальний uid піра):** з 1.1.12 діє authorize-before-dispatch
  гейт (`dispatchPrivOpFromMap` → `PrivOpsAuthzPure::authorize`,
  `lib/privops_authz_pure.cpp`), що enforce-ить пер-user власність для
  вербів із надійним сигналом власності, за `composeForUid`-env:
  `attach_zfs`/`detach_zfs` (`dataset` має бути в межах ZFS-префікса
  викликача `<master>/<uid>`) та
  `set_loginclass_rctl`/`clear_loginclass_rctl` (`loginclass` має бути
  `crate-<uid>` викликача). Чужа ціль → `403` ще до handler'а (fail
  closed). 1.1.13 поширює цей самий гейт на **jid- та name-scoped
  верби**: `set_rctl`, `clear_rctl`, `set_jail_cpuset`, `query_jail_rctl`,
  `signal_jail`, `destroy_jail`. Демон веде jid→owner-реєстр
  (`lib/jid_owner_registry.*`), фіксує uid оператора в момент
  `create_jail`; наступні верби від іншого оператора відбиваються `403`
  за тим самим реєстром. 1.1.14 додає до того ж реєстру longest-prefix
  `byPath`-резолвер і поширює гейт на **path-scoped верби** —
  `mount_nullfs` / `unmount_nullfs` (за `target`) та
  `apply_devfs_ruleset` / `add_devfs_unhide_rule` (за `mount_path`).
  Шлях, що лежить у jail, який в реєстрі належить іншому оператору,
  відбивається `403` (`DenyForeignPath`). 1.1.15 закриває останній
  вузький залишок: новенький `path`-аргумент `create_jail` зіставляється
  з пер-user `pathPrefix` викликача (виводиться з `path_master_prefix:`
  у crated.conf); чужа ціль → `403` (`DenyForeignCreatePath`).

Решта вербів проходить гейт: **host-global** верби
(iface/pf/ipfw/nat/epair) не можна розпулити — лишаються host-wide за
задумом. З 1.1.12+1.1.13+1.1.14+1.1.15 пер-тенант-гейт покриває
**кожен** privops-верб, що несе operator-controlled ownership-сигнал у
запиті. Обробники лишаються uid-сліпими; гейт іде попереду них.

> Наслідок: будь-хто, хто має доступ до privops — `admin` bearer-токен
> або членство в групі privops-сокета — досі має host-wide контроль над
> **не-гейтнутою** поверхнею (фаєрвол, інтерфейси, інші host-global
> верби спільного стану). Гейти 1.1.12 + 1.1.13 + 1.1.14 + 1.1.15
> закривають крос-тенантний доступ до ZFS-датасетів, RCTL-umbrella,
> jid-, name-, path-scoped та create-jail-path поверхні на libnv-шляху —
> кожен верб, що несе operator-controlled ownership-сигнал, тепер
> гейтнутий. Спільні host-global верби лишаються, за задумом, єдиним
> доменом довіри — для них видати оператору privops все ще близько до
> видачі старого setuid `crate(1)`.

### Per-user namespacing — це зручність, а не межа

Rootless-режим виводить пер-операторні шляхи, ZFS-префікси, мережеві
sub-CIDR та RCTL-umbrella-клас з uid оператора, що під'єднався
(`lib/per_user_*`, `lib/runtime_paths_pure.*`; див.
[`rootless-migration.md`](rootless-migration.md)). Це чисто розділяє
**чесних** операторів — jail'и `web` від alice і bob осідають у різних
ZFS-піддеревах і CIDR.

Це **не** ворожостійка межа на privops-площині. Пер-uid-префікс
рахується **на боці клієнта** (в `crate(1)`) і передається в запиті;
`crated` **не** перевиводить і не валідує `jid` / `dataset` / `path`
із запиту проти uid піра. Ворожий член privops-групи може зібрати сирий
nvlist-запит, що називає префікс іншого оператора, і `crated` його
виконає. Тож «bob can't run a jail in alice's ZFS prefix»
([`rootless-migration.md`](rootless-migration.md)) тримається для чесних
клієнтів через чесний `crate(1)`; це не межа, яку enforce-ить демон.
Enforce-нута ворожостійка ізоляція живе на Площині 2.

---

## Площина 2 — спостереження / контроль з пулами (ізольовано)

Непривілейована поверхня `crated`. Потенантна ізоляція enforce-иться на
точках входу, що несуть ідентичність викликача.

### 2a. Виділені control-сокети (0.7.10) — ізольовано

Пер-групові `AF_UNIX` сокети під `/var/run/crate/control/`, з трьома
рівнями захисту:

1. **Права ФС (ядро).** Сокет `chmod`-нуто до spec-mode і `chown`-нуто
   `root:<group>`, тож тільки члени групи можуть `connect(2)` —
   `daemon/control_socket.cpp:582,586`.
2. **`getpeereid(2)` re-check gid.** Навіть якщо mode послаблять, gid
   піра має дорівнювати очікуваному gid сокета —
   `daemon/control_socket.cpp:395`, що живить `ControlSocketPure::authorize`
   (`daemon/control_socket_pure.cpp:277`, `Decision::DenyGidMismatch`).
3. **Pool ACL.** Для пер-контейнерних дій пул контейнера
   (`PoolPure::inferPool`, `daemon/control_socket_pure.cpp:292`) має бути
   видимим у списку `pools` сокета — `poolVisibleOnSocket` (`:293`,
   визначено `:406`). Мутуючі дії (`PATCH resources`,
   `POST start`/`stop`/`restart`) додатково вимагають роль `admin`
   (`:282`, 0.8.13).

Результат: сокет alice (`pools: ["alice"]`) не може спостерігати,
патчити чи стартувати/спиняти jail у пулі bob. Це механізм, на який
покладається мультитенантне розгортання. Зауважте: ці сокети покривають
лише *control*-поверхню — вони **не** експонують `create_jail` /
`attach_zfs`, які є privops (Площина 1).

### 2b. Віддалені bearer-токени (0.7.1 scope, 0.7.4 pools) — ізольовано

HTTP-клієнти автентифікуються bearer-токеном, що несе термін дії
(`daemon/config.h:21`; `0` == ніколи), scope-глоби шляхів
(`daemon/config.h:26`; матчить `AuthPure::pathInScope`,
`lib/auth_pure.cpp:81`), роль і pool ACL (`daemon/config.h:31`).
`checkBearerAuthFull` гейтить термін + scope + роль
(`lib/auth_pure.cpp:101`); пер-контейнерний pool-гейт —
`isAuthorizedForContainer` → `PoolPure::tokenAllowsContainer`
(`daemon/auth.cpp:83-84`).

> Застереження: **`admin`**-bearer-токен також відмикає privops HTTP-
> площину (2a вище gated по ролі, privops gated по `admin`). Тож
> admin-токен — host-wide, **не** обмежений пулом. Лише
> `viewer`/pool-scoped токени несуть ізоляцію.

### 2c. ws-консоль, інтерактивний шелл — ізольовано (bearer + pool)

Websocket-консоль дає інтерактивний `jexec`-шелл усередині jail, тож її
гейт навантажений. Вона вимагає `admin` bearer-токен
(`daemon/ws_console.cpp:231`) **і** щоб пул jail був дозволений токеном
(`PoolPure::inferPool` / `tokenAllowsContainer`,
`daemon/ws_console.cpp:254-255`).

### 2d. Локальний Unix-сокет до головного HTTP API — НЕ ізольовано

Головний HTTP API `crated` також доступний через локальний Unix-сокет.
На цьому шляху cpp-httplib не віддає fd піра, тож `getpeereid(2)` не
підключено. **Unix-сокет-пірам довіряють цілком:**

- `isAuthorized` одразу повертає `true` для Unix-пірів, оминаючи
  bearer-auth — `daemon/auth.cpp:48-49`.
- `isAuthorizedForContainer` так само оминає pool ACL для Unix-пірів —
  `daemon/auth.cpp:74-75`.

Mode файлу сокета (типово `0660 root:wheel`) — *єдиний* гейт —
`daemon/auth.cpp:36-40`. Тож локальний доступ до головного API — це,
як і privops, **єдиний домен довіри**. Auth на основі `getpeereid` тут
ще попереду (roadmap §5.3). Лише виділені control-сокети (2a) несуть
пер-пул ідентичність локально.

---

## Інваріант, сформульований для імплементаторів

> **Міжтенантна ізоляція = pool ACL (control-сокет `pools`, токен
> `pools`) + scope токена, enforce-нуті на кожен запит, прив'язані до
> пулу цільового jail. Вона існує лише на точках входу, що несуть
> ідентичність викликача (Площина 2a/2b/2c). Privops-площина та
> Unix-сокет головного API — єдині домени довіри.**

Це контракт, який успадковує будь-яка нова привілейована поверхня.

---

## Відкритий розрив і guardrail для його закриття

1.1.12 почав закривати цей розрив: libnv-шлях тепер авторизує
`attach_zfs`/`detach_zfs` (за ZFS-префіксом) і loginclass-RCTL верби (за
`crate-<uid>`) перед диспетчеризацією. Решта Площини 1 — досі єдиний
домен довіри: host-wide `admin`-токен на HTTP, host-wide членство в групі
на libnv-сокеті для кожного не-гейтнутого верба. Це прийнятно **доки
доступ до privops трактується як еквівалент видачі старого setuid
`crate(1)`** — тобто видається лише цілком довіреним операторам.

Невирішене напруження: rootless-модель *вимагає*, щоб `crate(1)` мав
доступ до privops, аби взагалі створити jail, тоді як per-user
namespacing (вище) подається як мультитенантна ізоляція. Щоб зробити сам
privops безпечним для **взаємно недовірливих** операторів, для *кожного*
верба мусить виконуватись таке — інакше per-user-розділення є гігієною
для чесних операторів, а не межею безпеки:

1. **Авторизуй до диспетчеризації.** uid/gid від `getpeereid`
   *ідентифікує* викликача; він **не** *авторизує* операцію. Кожен
   привілейований верб має проганяти ownership-перевірку — тієї ж форми,
   що `poolVisibleOnSocket` / `tokenAllowsContainer` — прив'язану до
   **цільового** jail/пулу/датасета, *перед* виконанням операції.
   *Зроблено (1.1.12):* dataset- і loginclass-верби
   (`lib/privops_authz_pure.cpp`).
   *Зроблено (1.1.13):* jid- та name-scoped верби — `set_rctl`,
   `clear_rctl`, `set_jail_cpuset`, `query_jail_rctl`, `signal_jail`
   (за `jid`) і `destroy_jail` (за `name`). Демон веде
   **jid→owner-реєстр** (`lib/jid_owner_registry.*`, persist у
   `/var/db/crate/jid_owners.tsv`); uid оператора записується у момент
   `create_jail`; наступні jid/name-scoped верби від іншого оператора
   відбиваються `403` ще до handler'а. Jail-и, створені до 1.1.13, у
   реєстрі відсутні — bootstrap-поступка пропускає їх, щоб не зламати
   upgrade-шлях.
   *Зроблено (1.1.14):* path-scoped верби — `mount_nullfs` /
   `unmount_nullfs` (за `target`) та `apply_devfs_ruleset` /
   `add_devfs_unhide_rule` (за `mount_path`). Реєстр віддає
   longest-prefix `byPath`-лукап; шлях у jail, що належить іншому
   uid'ові, відбивається `403` (`DenyForeignPath`); шлях поза будь-яким
   зареєстрованим jail-ом проходить за тією ж bootstrap-поступкою.
   *Зроблено (1.1.15):* останній вузький залишок — `path`-аргумент
   `create_jail`. `PerUserEnvPure::Config` отримав `pathMasterPrefix`
   (конфіг у crated.conf через `path_master_prefix:`); `composeForUid()`
   виводить `env.pathPrefix = <master>/<uid>`. Гейт виконує
   `PrivOpsAuthzPure::pathOwned(req.path, env.pathPrefix)` —
   slash-anchored prefix-match тієї ж форми, що `datasetOwned` для ZFS.
   Чужа ціль → `403` (`DenyForeignCreatePath`). Порожній
   `pathMasterPrefix` зберігає легасі-форму (Allow), щоб існуючим
   deployment-ам не доводилось переконфігуруватись на апгрейді.

2. **Пер-операторний namespacing — це зручність, а не межа.** Будь-який
   аргумент `path` / `jid` / `dataset`, що перетинає privops-сокет, має
   бути перевиведений або зваліджований **на боці демона** проти
   uid-префікса викликача — ніколи не братись на віру. *Зроблено* для
   `dataset` (1.1.12), для `jid` / `name` jail-у (1.1.13, через реєстр),
   для path-scoped runtime-вербів (1.1.14, longest-prefix `byPath` на
   тому ж реєстрі) та для новенького шляху `create_jail` (1.1.15,
   slash-anchored prefix проти `env.pathPrefix`).

3. **Fail closed при втраті ідентичності.** На будь-якому шляху, що
   авторизує, збій `getpeereid` має давати deny. Деградувати до no-op
   можна лише для side-effect'ів з тегом ідентичності, що не є рішеннями
   доступу (напр. audit-хвіст — його теперішня поведінка).

Доки jid-scoped верби з (1) не гейтнуті, мультитенантне розгортання, де
оператори мають самі створювати jail'и, має посередничати створення jail
через довірений брокер, а не видавати операторам сирий доступ до
privops-сокета.

---

## Рекомендації для розгортання (взаємно недовірливі тенанти)

- **Видавайте недовіреним операторам:** лише pool-scoped виділений
  control-сокет (2a) та/або `viewer`/pool-scoped bearer-токен (2b).
- **Не видавайте недовіреним операторам:** доступ до privops-сокета (по
  групі), `admin`-bearer-токен, Unix-сокет головного API чи `crate(1)`,
  якому потрібен privops для створення jail'ів.
- Розділення чесних операторів (per-user шляхи/датасети/CIDR) та
  enforce-нута ворожостійка ізоляція (pool-ACL'нута Площина 2) — це різні
  гарантії; не плутайте їх.

### Експозиція GUI-пристроїв (`gui.mode: compositor`)

Запуск Wayland-композитора всередині jail може відкрити вузли
пристроїв хоста, які типовий devfs-ruleset ховає:

- **`gui.backend: headless`** (за замовчуванням) — рендер офскрін,
  віддається через VNC (`wayvnc`). **Не відкриває input-пристроїв**;
  торкається `/dev/dri/*` лише за наявності render-вузла (GPU-
  прискорення). Безпечно для напівдовіреного навантаження.
- **`gui.backend: drm`** — jail напряму керує фізичним GPU та input.
  crate робить unhide **`/dev/dri/*` та `/dev/input/*`** у devfs-
  в'юшці jail'а і прокидає хостовий `seatd`-сокет. Це справжня
  привілейована поверхня: процес у такому jail може читати **всі**
  події вводу по всьому хосту (кожне натискання клавіш, кожен рух
  вказівника) і працювати з GPU на рівні KMS. Вважайте jail з
  бекендом `drm` частиною довіреного дисплейного домену хоста — **не**
  видавайте його взаємно недовірливому тенанту. Він opt-in саме тому,
  що дефолт (`headless`) цієї експозиції уникає.

---

## Див. також

- [`rootless-migration.md`](rootless-migration.md) — міграція
  setuid → privops (0.9.0–1.0.0) і per-user-модель.
- [`security-command-paths.md`](security-command-paths.md) — абсолютні
  шляхи команд / санітизація env (CWE-426). Тепер найрелевантніше для
  `crated`, бо саме цей процес запускає host-інструменти від root.
- [`implementation-roadmap.md`](implementation-roadmap.md) §5.1
  (високорівневі REST write-ендпоінти), §5.3 (`getpeereid`-auth на
  головному API).
