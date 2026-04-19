Весь код сгенерирован Grok Code.

# opkssh-oidc Prototype

Локальный прототип для проверки сценария OIDC + SSH сертификатов по RFC variant 2.

## Архитектура

- **Локальный OIDC API** (`internal/api`): Симулирует OIDC provider с эндпоинтами `/token`, `/jwks`, `/users`, `/groups`.
- **OIDC токены** (`internal/oidc`): Генерация Ed25519-подписанных ID токенов с claims (email, groups).
- **SSH сертификаты** (`internal/ssh`): CA на Ed25519, пользовательские сертификаты с embedded ID токенами.
- **CLI** (`cmd/qwe`): Команды для сервера, логина, генерации сертификатов, верификации.

## Запуск

1. **Собрать проект:**
   ```bash
   go build -o qwe ./cmd/qwe
   ```

2. **Запустить локальный OIDC API сервер:**
   ```bash
   ./qwe serve
   ```
   Сервер слушает на `:8080`.

3. **Залогиниться и получить токен:**
   ```bash
   ./qwe login --user alice
   ```
   Сохраняет токен в `~/.qwe/token.json`.

4. **Сгенерировать SSH сертификат:**
   ```bash
   ./qwe ssh --user alice --cert-only dummy
   ```
   Создаёт `~/.qwe/alice-cert.pub`.

5. **Проверить сертификат:**
   ```bash
   ./qwe verify ~/.qwe/alice-cert.pub
   ```
   Выводит группы и права sudo.

## SSH интеграция

Для использования как `AuthorizedKeysCommand`:

```bash
# В /etc/ssh/sshd_config добавить:
AuthorizedKeysCommand /path/to/qwe auth-keys %u %k %t
AuthorizedKeysCommandUser nobody
```

Тогда `./qwe auth-keys alice <cert> ssh-ed25519-cert-v01@openssh.com` проверит сертификат и выведет его, если авторизован.

## Тестовые пользователи

- **alice**: группы `cluster-1:admin`, `cluster-1:dev` → sudo=true
- **bob**: группы `cluster-1:view` → sudo=false

## Структура проекта

- `cmd/qwe/main.go` — CLI с командами `serve`, `login`, `ssh`, `verify`, `auth-keys`.
- `internal/api/data.go` — тестовые данные пользователей/групп.
- `internal/api/server.go` — HTTP обработчики.
- `internal/oidc/token.go` — генерация JWT ID токенов.
- `internal/oidc/verify.go` — проверка токенов.
- `internal/ssh/cert.go` — SSH CA, ключи, сертификаты, проверка.

## Как использовать

1. Запустить локальный API:

```bash
cd /Users/mastervolkov/Documents/golang/opkssh-oidc
go build -o qwe ./cmd/qwe
./qwe serve &
```

2. В другом терминале получить token для пользователя `alice`:

```bash
./qwe login --user alice
```

3. Проверить сертификат:

```bash
./qwe verify ~/.qwe/alice-cert.pub
```

Вывод:
```
verified certificate for alice
groups: cluster-1:admin, cluster-1:dev
authorized sudo: true
```

## API

- `/.well-known/openid-configuration`
- `/jwks`
- `/token` — POST с `{"username": "alice"}` для получения ID токена
- `/users`
- `/groups`

## Тестирование полного флоу

Для полного тестирования SSH-подключения нужен SSH-сервер с opkssh. В прототипе реализован вариант 2 из RFC: octoctl генерирует SSH-сертификаты.

Чтобы протестировать `./qwe ssh <ip> --user alice`, нужен сервер с opkssh, настроенный на использование локального API как OIDC-провайдера.

## NCC модуль (OS Login)

NCC код адаптирован для использования локального API вместо GCP metadata server:

- `kMetadataServerUrl` изменён на `"http://127.0.0.1:8080/"`
- Реализованы `HttpGet`, `ParseJsonToPasswd` и функции для групп с использованием libcurl и regex для парсинга JSON
- Убрана зависимость от кэш файлов; прямые HTTP запросы к API
- API расширено поддержкой `?name=` и `?gid=` для групп

Для компиляции на Linux (с NSS):
```bash
make  # Требует libcurl-dev, NSS headers
```

Модуль позволяет NSS (getpwnam, getpwuid, getgrnam, getgrgid) запрашивать данные из локального OIDC API.

## Замечания

- Сертификаты подписываются локальным CA, хранящимся в `~/.qwe/ca`.
- `qwe` создаёт ключи `~/.qwe/<username>` и сертификат `~/.qwe/<username>-cert.pub`.
- `verify` проверяет сертификат и ID токен по локальному JWKS.
