# Развёртывание с нуля

## 1. VPS

Базовый вариант: **Ubuntu Server 24.04 LTS, KVM, amd64 или arm64**, публичный IPv4,
1–2 vCPU, от 1 ГБ RAM (для сборки лучше 2 ГБ) и от 10 ГБ диска. Это стартовые
ориентиры, пропускную способность нужно измерять: userspace VPN расходует CPU.
Нужны SSH-доступ с `sudo`, выход в интернет для GitHub/Docker Hub и поддержка TUN.
На OpenVZ/LXC возможность TUN и нужных сетевых операций зависит от провайдера.

Команды ниже выполняются **на новом Linux VPS**. Не на Windows и не на старом сервере.
В примерах каталог VPN — `/opt/aegis-vpn`. Если выбрали `/root/VPN-server` или
другой путь, используйте его во всех командах; каталоги VPN и сайта различаются.

```bash
sudo apt update
sudo apt install -y ca-certificates curl git python3 age
test -c /dev/net/tun && echo 'TUN available'
```

Если TUN отсутствует, выполните `sudo modprobe tun` и повторите проверку.
Если провайдер не предоставляет TUN, данный комплект на этом VPS не запустится.

## 2. Docker Engine и Compose

Для чистой Ubuntu используйте официальный репозиторий Docker:

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker version
sudo docker compose version
```

Нужен актуальный Compose v2 с поддержкой `up --wait` (2.20+). Если Docker уже установлен,
сначала проверьте его версию; удалять рабочую установку и данные не нужно.
Источник: [Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/).

Дальше используется root-сеанс, чтобы каталоги с ключами были доступны только root:

```bash
sudo -i
install -d -m 700 /opt/aegis-vpn
```

## 3. Скопировать этот каталог

С локального компьютера экспортируйте выбранную Git-версию комплекта отдельно от сайта.
Подставьте путь к checkout; пример для Windows:

```powershell
git -C D:\VPN-server archive --format=tar --output="$env:TEMP\aegis-vpn-kit.tar" HEAD
scp "$env:TEMP\aegis-vpn-kit.tar" your-ssh-user@YOUR_VPS_IP:~/aegis-vpn-kit.tar
```

`git archive HEAD` включает только файлы выбранного коммита. Нужные изменения должны
входить в этот коммит; `.env`, данные, секреты, `.git` и локальные выгрузки не копируются.
Для репозитория с настроенным доступом можно вместо архива клонировать его на VPS
в пустой каталог и перейти к разделу 4.

В root-сеансе VPS (подставьте пользователя):

```bash
test -z "$(ls -A /opt/aegis-vpn)" || { echo 'Deployment directory must be empty'; exit 1; }
tar --extract --file=/home/your-ssh-user/aegis-vpn-kit.tar --directory=/opt/aegis-vpn --no-same-owner
chown -R root:root /opt/aegis-vpn
chmod 700 /opt/aegis-vpn
cd /opt/aegis-vpn
```

Это команда **первого развёртывания**. При обновлениях не затирайте `.env`, `data/`
и `secrets/` новой пустой копией; порядок обновления описан отдельно.
Каталог самодостаточный: проекты ботов и PostgreSQL для VPN не нужны.

## 4. Внешний адрес и порты

Если есть домен, создайте A-запись, например `vpn.your-domain.ru`, на публичный IPv4 VPS.
Для записи VPN отключите HTTP/CDN proxy: нужен прямой UDP-доступ. Домен не обязателен,
можно использовать сам IPv4. Не публикуйте AAAA-запись без настроенного внешнего IPv6.

В firewall провайдера разрешите:

- ваш SSH TCP-порт только с нужных административных адресов;
- выбранный **UDP-порт VPN**, по умолчанию **443/udp**, для клиентов.

Порт **8787/tcp не открывать**. HTTPS-сайту нужны отдельные 80/443 TCP, только если
вы разворачиваете сайт на том же VPS. UDP 443 и TCP 443 могут сосуществовать;
HTTP/3/QUIC на UDP 443 будет конфликтовать — тогда выберите для VPN другой UDP-порт.

Если UFW уже активен, разрешите выбранный UDP-порт (`ufw allow 443/udp`). Не включайте
UFW удалённо без правила для своего SSH-порта. Docker обрабатывает опубликованные
порты собственными правилами: UFW сам по себе не гарантирует их фильтрацию.
Источник: [Docker packet filtering](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

## 5. Первоначальные настройки

```bash
cd /opt/aegis-vpn
python3 scripts/setup.py --endpoint vpn.your-domain.ru --port 443
```

Подставьте настоящий адрес. Скрипт один раз создаёт `.env`, ключ шифрования и API-токен.
Секреты не выводятся в терминал. Если установка уже есть, скрипт откажется её затереть.

До первого запуска проверьте `.env`:

```bash
nano .env
docker compose config --quiet
```

`VPN_SUBNET=10.77.0.0/24` не должен пересекаться с LAN, Docker-сетями или другими VPN.
В этом диапазоне доступно 253 клиентских адреса. Позже подсеть нельзя просто заменить
без перевыдачи конфигураций. `VPN_MTU=1280` выбран консервативно с учётом обфускации.
DNS по умолчанию — публичные IPv4-резолверы; можно указать другие публичные адреса.

## 6. Сборка и запуск

```bash
docker compose build --pull vpn
docker compose up -d --wait --wait-timeout 120
docker compose ps
docker compose exec -T vpn python3 /opt/aegis/agent.py health
```

Ожидается `healthy` и `{"ready": true}`. При первом старте автоматически создаются
серверные ключи и параметры AmneziaWG 3.1. Повторный старт использует те же данные.
Сборка требует доступа к официальным репозиториям Amnezia и реестру Docker.

## 7. Первое реальное подключение

```bash
bash scripts/smoke-test.sh
docker compose exec -T vpn python3 /opt/aegis/agent.py create first-phone --name 'Первый телефон'
umask 077
docker compose exec -T vpn python3 /opt/aegis/agent.py config first-phone > exports/first-phone.conf
```

Передайте файл на своё устройство защищённым способом. Он содержит приватный ключ.
Используйте приложение с поддержкой **AmneziaWG 3.1**. Обычный WireGuard, а также клиенты
только для AWG 1.x/2.0 этот профиль не поддерживают. По официальной инструкции переход
на 3.1 требует актуального AmneziaVPN (рекомендуется 5.0.2.1 или новее); проверьте текущую
поддержку конкретной платформы: [AmneziaWG self-hosted](https://docs.amnezia.org/documentation/instructions/new-amneziawg-selfhosted/).

Импортируйте `.conf` как клиентское подключение. **Не добавляйте VPS с root-паролем
в AmneziaVPN для автоматической установки**: сервером уже управляет этот Compose-проект.

После включения проверьте:

1. Открывается обычный сайт; внешний IPv4 совпадает с VPS.
2. DNS работает; IPv6 не выходит напрямую мимо туннеля.
3. На VPS виден недавний handshake:
   `docker compose exec -T vpn awg show awg0 latest-handshakes`.
4. Отключение действительно прекращает доступ, включение восстанавливает его:
   `docker compose exec -T vpn python3 /opt/aegis/agent.py disable first-phone`,
   затем та же команда с `enable first-phone`.
5. После `docker compose restart vpn` и перезагрузки VPS старый файл продолжает работать.

`healthy` проверяет локальную готовность, а не доступность UDP у провайдера и не обход
конкретных сетевых ограничений. Реальный тест телефона/ПК обязателен.

## 8. Резервная копия и сайт

Сразу настройте [шифрованный бэкап](BACKUP-UPDATE.md). До подключения сайта устройствами
можно управлять [через CLI](OPERATIONS.md). Для автоматизации используйте
[контракт API и защищённое соединение](INTEGRATION.md).
