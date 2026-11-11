# TicketBridge

Мост «Graylog → GLPI + DFIR-IRIS» маршрутизирует алерты по приоритету:
High создаёт заявку GLPI со ссылками на разбор в HomeWiki, отчёт TrafficLens
и кнопкой блокировки IOC в BlockBoard, а также алерт в IRIS; Medium и Low
создают только алерт IRIS и не перегружают GLPI. Действия логируются обратно
в Graylog (GELF). Поддерживаются IRIS v2 (`POST /alerts/add`) и v3
(`POST /api/v2/alerts`), включая разные форматы ответа. Для передачи в IRIS
нужны `TB_IRIS_URL` и `TB_IRIS_KEY`; без них мост продолжает обрабатывать GLPI.

```
Graylog (HTTP notification) --POST /hook?key=...--> TicketBridge --REST--> GLPI Ticket
                                                             \--REST--> DFIR-IRIS Alert
```

## Скриншоты

![Заявки GLPI, созданные из алертов Graylog](docs/screenshots/glpi-tickets.png)

## Корреляция инцидентов

Повторный алерт того же хоста (ключ: `fields.host` / `source` /
`event.key`) в течение окна `TB_CORR_WINDOW` (по умолчанию 1800 с)
не создаёт новый тикет, а дописывается **followup**'ом в уже открытый
— один инцидент вместо серии дублей. Закрытый тикет или истёкшее окно —
новый тикет. Состояние — в SQLite `state.db` рядом с приложением.

## Установка (сервер)

```bash
mkdir -p ~/ticketbridge && cp app.py ~/ticketbridge/
cp ticketbridge.env ~/ticketbridge/   # заполнить токены GLPI
cp systemd/ticketbridge.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now ticketbridge
```

## Настройка DFIR-IRIS

- IRIS v2.4.x: `TB_IRIS_API_PATH=/alerts/add` (значение по умолчанию в коде).
- IRIS v3: `TB_IRIS_API_PATH=/api/v2/alerts`.

В нашей лаборатории с 11.11.2026 используется IRIS v3.0.0-beta.23 и
`TB_IRIS_API_PATH=/api/v2/alerts`; пример `ticketbridge.env.example` соответствует
этой конфигурации.

Путь должен начинаться с `/` и относиться к хосту из `TB_IRIS_URL`. API-ключ
передаётся как `Authorization: Bearer <TB_IRIS_KEY>`. Для v3 проверено создание
алерта с HTTP 201 и чтение прямого JSON-объекта без обёртки `status: success`.

### Source Link → Graylog Replay Search

Поле **Source Link** в новых алертах IRIS ведёт на повторный поиск конкретного
события Graylog: `<TB_GRAYLOG_URL>/alerts/<event.id>/replay-search`. Маршрут
соответствует Graylog 7.2.1 и использует `id` из HTTP-уведомления, поэтому
дополнительные запросы к API не нужны. Если у нестандартного события нет `id`,
используется резервная ссылка `<TB_GRAYLOG_URL>/alerts`.

Публичный адрес задаётся переменной `TB_GRAYLOG_URL` (по умолчанию
`https://graylog.apps.monitoring.test`). Уже созданные алерты IRIS не изменяются
автоматически: новая ссылка появляется у событий, принятых после обновления.

### Приоритеты и взятие в работу

Сопоставление приоритетов: Graylog 3 → IRIS **High** (5), 2 → **Medium** (1),
1 → **Low** (4). В GLPI попадает только High; для него urgency равна 5.
Аналитик может изменить приоритет в карточке: **алерт → Edit → Severity → Save**.

В лаборатории добавлен overlay `deploy/iris/alerts.py` для IRIS v3: штатное
поведение не сообщает пользователю о его собственных действиях, а overlay
отправляет письмо `alert_assigned`, когда владелец впервые становится текущим
пользователем или меняется на него. Повторное редактирование Severity,
описания и других полей своего алерта нового письма не создаёт. Для работы
нужны настроенный SMTP, адрес пользователя и включённое email-уведомление
**Alert assigned** в его профиле.

Файл подключается только к сервису `app`, не к `worker`:

```yaml
- ./custom/business/alerts.py:/iriswebapp/app/business/alerts.py:ro,z
```

После копирования файла в `custom/business/alerts.py` выполнить
`podman-compose up -d app`. При обновлении версии IRIS overlay нужно сверить
с новым `app/business/alerts.py`, а не переносить вслепую.

## Подготовка GLPI

1. Настройка → Общие → API: включить REST API.
2. Там же добавить API-клиента → получить **app_token**.
3. Администрирование → Пользователи → служебный пользователь →
   ключи удалённого доступа → **user_token**.

Оба токена — в `ticketbridge.env` (`TB_GLPI_APP_TOKEN`, `TB_GLPI_USER_TOKEN`).

## Автозакрытие (цикл MTTR)

- **Восстановление**: событие вида `agent_recovered` / «вернулся» по тому же
  хосту закрывает открытый тикет с комментарием (правило Graylog
  «HOMEREPO - Агент вернулся на связь» шлёт только вебхук, без письма).
- **TTL**: раз в 30 минут фоновый sweeper закрывает инциденты, по которым
  нет новых алертов дольше `TB_CLOSE_AFTER` (по умолчанию 24 ч) — с
  комментарием «Автозакрытие: тишина».
- События `tb_event=closed_recovery` / `autoclose` уходят в Graylog, так что
  Lab Score видит честное время жизни тикетов (MTTR).

## Graylog

System → Alerts → Notifications → HTTP Notification:
URL `http://127.0.0.1:8099/hook?key=<TB_KEY>`. Одно уведомление
`GLPI Ticket (TicketBridge)` привязывается ко **всем активным правилам**,
а мост сам разделяет маршруты GLPI и IRIS по приоритету.

Для безопасной массовой привязки используется `tools/sync_graylog_iris.py`:

```bash
export GRAYLOG_URL='https://graylog.apps.monitoring.test'
export GRAYLOG_TOKEN='<access-token>'
python3 tools/sync_graylog_iris.py             # только dry-run
python3 tools/sync_graylog_iris.py --apply     # backup, обновление, проверка
```

Скрипт не меняет отключённые правила и правила с `alert=false`, перед записью
повторно читает каждое определение и сохраняет JSON-копии с правами `0600` в
`~/ticketbridge/backups/iris-all-alerts-<timestamp>/`. Для пилота есть
`--only-id <event-definition-id>`. На 11.11.2026 проверена привязка 255/255
активных правил; сквозные тесты Low, Medium и High подтвердили создание алертов
IRIS, при этом GLPI-заявки для Low и Medium не создаются.

## Проверка

```bash
curl -X POST 'http://127.0.0.1:8099/hook?key=<TB_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"event":{"message":"Тест","timestamp":"...","priority":3,"event_definition_id":"...","fields":{}}}'
```

События в Graylog: `tool:ticketbridge`.
