# opkssh-oidc

SSH-доступ к серверам через OIDC-аутентификацию с использованием короткоживущих SSH-сертификатов.

## Как это работает

1. Клиент запрашивает OIDC-токен у API-сервера (`qwe serve`).
2. Генерирует SSH-ключ и сертификат с вшитым ID-токеном.
3. Подключается к серверу по SSH с этим сертификатом.
4. На сервере `AuthorizedKeysCommand` проверяет CA-подпись и верифицирует OIDC-токен.
5. NSS-модуль резолвит пользователя (UID/GID/home) через API.

---

## Подключение к серверу (клиент)

### Требования

- Go 1.21+
- `ssh-keygen` (предустановлен в macOS/Linux)

### Сборка

```bash
git clone https://github.com/mastervolkov/opkssh-oidc.git
cd opkssh-oidc
make
```

### Подключение

```bash
./qwe ssh <server-ip> --user alice --api-url http://<server-ip>:8080
```

Пример:

```bash
./qwe ssh 83.222.9.29 --user alice --api-url http://83.222.9.29:8080
```

Это автоматически:
- получит OIDC-токен от сервера;
- сгенерирует SSH-ключ (если нет);
- создаст CA (если нет);
- выпустит SSH-сертификат (15 мин TTL) с вшитым токеном;
- подключится по SSH.

Ключи и сертификаты сохраняются в `~/.qwe/`.

### Доступные пользователи (тестовые)

| Пользователь | Группы | Sudo |
|---|---|---|
| alice | cluster-1:admin, cluster-1:dev | да |
| bob | cluster-1:view | нет |

### Дополнительные команды

```bash
# Только получить токен (без SSH)
./qwe login --user alice --api-url http://<server-ip>:8080

# Только создать сертификат (без подключения)
./qwe ssh <server-ip> --user alice --api-url http://<server-ip>:8080 --cert-only

# Проверить сертификат
./qwe verify ~/.qwe/alice-cert.pub --api-url http://<server-ip>:8080
```

---

## Настройка сервера

### 1. Установить зависимости

```bash
apt-get update
apt-get install -y golang-go g++ libcurl4-openssl-dev
```

### 2. Собрать бинарник и NSS-модуль

```bash
git clone https://github.com/mastervolkov/opkssh-oidc.git
cd opkssh-oidc
make          # собирает бинарник qwe
make nss      # собирает libnss_oslogin.so
```

Или собрать бинарник на другой машине для Linux:

```bash
GOOS=linux GOARCH=amd64 make
```

### 3. Установить бинарник

```bash
cp qwe /usr/local/bin/qwe
chmod +x /usr/local/bin/qwe
```

### 4. Установить NSS-модуль

```bash
cp libnss_oslogin.so /lib/x86_64-linux-gnu/libnss_oslogin.so.2
ldconfig
```

Добавить `oslogin` в `/etc/nsswitch.conf`:

```
passwd: files oslogin
group:  files oslogin
```

Проверить:

```bash
# После запуска qwe serve
getent passwd alice
# alice:*:1001:1001:Alice Example:/home/alice:/bin/bash
```

### 5. Запустить API-сервер

Создать systemd-сервис `/etc/systemd/system/qwe.service`:

```ini
[Unit]
Description=QWE OIDC API Server
After=network.target

[Service]
ExecStart=/usr/local/bin/qwe serve
Environment=QWE_ISSUER=http://<server-ip>:8080
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now qwe
```

Проверить: `curl http://127.0.0.1:8080/`

### 6. Подготовить директорию для CA

```bash
mkdir -p /etc/qwe
```

CA-ключ будет скопирован автоматически при первом подключении клиента (вручную):

```bash
# С клиента после первого ./qwe ssh --cert-only:
scp ~/.qwe/ca.pub root@<server-ip>:/etc/qwe/ca.pub
```

### 7. Настроить sshd

Добавить в `/etc/ssh/sshd_config`:

```
AuthorizedKeysCommand /usr/local/bin/qwe --data-dir /etc/qwe --api-url http://<server-ip>:8080 auth-keys %u %k %t
AuthorizedKeysCommandUser nobody
```

```bash
systemctl restart ssh
```

### 8. Создать home-директории (опционально)

```bash
mkdir -p /home/alice /home/bob
chown 1001:1001 /home/alice
chown 1002:1002 /home/bob
```

Или включить автосоздание через PAM — добавить в `/etc/pam.d/sshd`:

```
session required pam_mkhomedir.so skel=/etc/skel umask=0022
```

---

## Проверка работоспособности

### На сервере

```bash
# API работает
curl http://127.0.0.1:8080/users?username=alice

# NSS резолвит пользователей
getent passwd alice

# auth-keys вручную (подставить base64 из сертификата)
sudo -u nobody /usr/local/bin/qwe --data-dir /etc/qwe --api-url http://<server-ip>:8080 auth-keys alice <base64> ssh-ed25519-cert-v01@openssh.com

# Логи sshd
journalctl -u ssh -f
```

### На клиенте

```bash
# Проверить сертификат
ssh-keygen -L -f ~/.qwe/alice-cert.pub

# Верифицировать токен
./qwe verify ~/.qwe/alice-cert.pub --api-url http://<server-ip>:8080

# Подключиться с debug
ssh -vvv -i ~/.qwe/alice -o CertificateFile=~/.qwe/alice-cert.pub alice@<server-ip>
```

---

## Архитектура

```
Клиент                          Сервер
──────                          ──────
qwe ssh <ip> --user alice
  │
  ├─ POST /token ──────────────► qwe serve (OIDC API :8080)
  │◄── id_token ◄──────────────┤
  │                              │
  ├─ ssh-keygen (CA + user key) │
  ├─ sign cert (KeyId=user|jwt) │
  │                              │
  ├─ SSH connect ──────────────► sshd
  │                              │ ├─ AuthorizedKeysCommand
  │                              │ │   └─ qwe auth-keys %u %k %t
  │                              │ │       ├─ parse cert from %k
  │                              │ │       ├─ verify CA signature
  │                              │ │       ├─ extract & verify OIDC token
  │                              │ │       └─ output: cert-authority <ca.pub>
  │                              │ ├─ sshd verifies cert signature
  │                              │ └─ NSS (libnss_oslogin.so)
  │                              │       └─ GET /users?username=alice
  │◄── SSH session ◄────────────┤
```

## Структура проекта

```
cmd/qwe/main.go          CLI: serve, login, ssh, verify, auth-keys
internal/api/             OIDC API сервер (тестовые пользователи, /token, /jwks, /users, /groups)
internal/oidc/            JWT-токены: выпуск (EdDSA) и верификация через JWKS
internal/ssh/             SSH CA, генерация ключей, создание и проверка сертификатов
nss/                      NSS-модуль (C++) для резолва пользователей через API
```
