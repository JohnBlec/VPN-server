# SSH-туннель из Docker backend

Для публичного сайта на Ubuntu 22.04 используйте новую
[production-инструкцию](D:/VPN_Web-app/VPN_Web-app/docs/production-ubuntu.md):
в ней готовые HTTPS и туннели для того же VPS и нескольких удалённых VPS.
Этот файл описывает прежний вариант для локального Compose сайта.

Этот дополнительный Compose-файл запускается **на сервере сайта**, из корня проекта.
Сам комплект хранится отдельно от сайта: локально `D:\VPN-server`, на Linux-хосте
сайта скопируйте его, например, в `/opt/aegis-vpn-kit`. Команды ниже выполняются в Bash
на сервере сайта. Задайте абсолютный путь к этой копии:

```bash
export VPN_SERVER_DIR=/opt/aegis-vpn-kit
```

Он даёт backend доступ к `http://127.0.0.1:18787`, не публикуя порт туннеля наружу.
Контейнер разделяет сетевое пространство `backend`. Адаптер Django реализован. Полная инструкция запуска backend и worker:
[Django + VPN](D:/VPN_Web-app/VPN_Web-app/docs/vpn-integration.md).
Корневой Compose сайта сейчас предназначен для разработки; туннель не превращает его
в production-развёртывание с HTTPS, отключённым DEBUG и резервным копированием БД.

1. На хосте сайта создайте отдельный ключ (каталог и файлы не входят в Git):

   ```bash
   install -d -m 700 "$VPN_SERVER_DIR/integration/secrets"
   ssh-keygen -t ed25519 -N '' -f "$VPN_SERVER_DIR/integration/secrets/id_ed25519"
   ```

2. На VPN-хосте заведите ограниченного SSH-пользователя и установите публичный ключ
   по [инструкции](../docs/INTEGRATION.md). В firewall разрешите SSH с IP сервера сайта.
   Приватный ключ остаётся на сервере сайта.
3. Сохраните ключ VPN-хоста в `$VPN_SERVER_DIR/integration/secrets/known_hosts`, сверив
   fingerprint через доверенный сеанс. Для нестандартного порта запись имеет вид
   `[vpn.your-domain.ru]:2222 ...`. Можно получить кандидата через `ssh-keyscan -p 22 HOST`,
   но использовать его только после сверки. Имя в записи должно совпадать с VPN_SSH_HOST.
4. Скопируйте токен агента в `$VPN_SERVER_DIR/integration/secrets/agent_token`.
   Файл должен читаться UID 10001 backend/worker (например, owner 10001, mode 640).
   Не передавайте его frontend.
5. В **корневой `.env` сайта** добавьте `VPN_SSH_HOST=...`, `VPN_SSH_PORT=22`,
   `VPN_SSH_USER=aegis-agent` и `VPN_SERVER_DIR=/opt/aegis-vpn-kit`.
   Это не `.env` VPN-сервера. Затем из каталога сайта:

   ```bash
   docker compose -f compose.yml -f "$VPN_SERVER_DIR/integration/compose.tunnel.yml" up -d --build
   docker compose -f compose.yml -f "$VPN_SERVER_DIR/integration/compose.tunnel.yml" logs --tail 30 vpn-tunnel
   docker compose exec -T backend python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:18787/healthz', timeout=10).read().decode())"
   ```

Ожидается `{"ready": true}`. Туннель запускается после создания backend, однако SSH
может подключиться позже: worker должен повторять запросы после ошибок связи.
При пересоздании backend пересоздавайте vpn-worker и vpn-tunnel (он использует его сетевое пространство):

```bash
docker compose --profile vpn -f compose.yml -f "$VPN_SERVER_DIR/integration/compose.tunnel.yml" up -d --force-recreate backend vpn-worker vpn-tunnel
```

Передавайте API-токен отдельно только backend/worker через защищённый secret; SSH-ключ
не заменяет bearer-токен. Туннель не нуждается в API-токене. В текущем Compose worker явно использует network_mode: service:backend,
поэтому туннель доступен ему по тому же localhost. При изменении этой схемы
понадобится отдельный закрытый транспорт.

При размещении на одном VPS используйте доступный контейнеру адрес SSH-хоста, например
его публичный IP (если разрешён такой маршрут). `127.0.0.1` в VPN_SSH_HOST укажет на
backend, а не на SSH-сервер VPS.
