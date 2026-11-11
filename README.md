# TicketBridge

Мост «Graylog → GLPI + DFIR-IRIS»: HTTP-уведомление Graylog о High-алерте превращается
в тикет GLPI со ссылками на разбор в HomeWiki, отчёт TrafficLens и кнопкой
блокировки IOC в BlockBoard. Действия логируются обратно в Graylog (GELF).
Дополнительно каждый алерт дублируется в DFIR-IRIS для триажа и расследования
инцидентов ИБ (если заданы `TB_IRIS_URL` и `TB_IRIS_KEY`). Поддерживаются IRIS v2
(`POST /alerts/add`) и v3 (`POST /api/v2/alerts`), включая разные форматы ответа.

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
URL `http://127.0.0.1:8099/hook?key=<TB_KEY>`. Привязать к правилам
с приоритетом High. Приоритет 3 → urgency 5, 2 → 3, 1 → 1.

## Проверка

```bash
curl -X POST 'http://127.0.0.1:8099/hook?key=<TB_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"event":{"message":"Тест","timestamp":"...","priority":3,"event_definition_id":"...","fields":{}}}'
```

События в Graylog: `tool:ticketbridge`.
