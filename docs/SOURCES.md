# Версии и источники

Исходники зафиксированы при подготовке комплекта 25.09.2026; инструкции Docker,
совместимости AmneziaWG и параметры закреплённого README повторно сверены 01.10.2026.
Это собственная обвязка управления
официальными открытыми компонентами; HTTP API Aegis не является API Amnezia.

| Компонент | Закреплённая версия |
|---|---|
| [AmneziaWG Go](https://github.com/amnezia-vpn/amneziawg-go) | [v3.1.20260828](https://github.com/amnezia-vpn/amneziawg-go/releases/tag/v3.1.20260828), commit `b5928efb6ca19f0153958460c3d141f04abc5c2e` |
| [AmneziaWG tools](https://github.com/amnezia-vpn/amneziawg-tools) | [v3.1.20260812](https://github.com/amnezia-vpn/amneziawg-tools/releases/tag/v3.1.20260812), commit `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` |

Dockerfile получает точный commit и проверяет его перед сборкой. Базовые образы Debian,
Go и пакеты apt получают исправления при новой сборке; для точного отката сохраняйте
предыдущий готовый образ. Закрепление исходников не означает проведённый аудит безопасности.

Реализация Go работает через TUN без модуля AmneziaWG в ядре хоста. Это упрощает
обновления, но производительность зависит от CPU и требует замера на вашем VPS.
Параметры `HeaderProtectionKey`, S1–S4 и `ContentPaddingAddition` взяты из
[README закреплённой версии](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/README.md).

Клиент должен поддерживать AmneziaWG 3.1. Официальная
[инструкция self-hosted](https://docs.amnezia.org/documentation/instructions/new-amneziawg-selfhosted/)
рекомендует AmneziaVPN 5.0.2.1 или новее. Поддержку импорта `.conf` проверьте на
конкретной платформе. Настройка не гарантирует доступность при любых ограничениях сети.

Другие первичные источники:

- [Установка Docker Engine на Ubuntu](https://docs.docker.com/engine/install/ubuntu/).
- [Docker и правила фильтрации трафика](https://docs.docker.com/engine/network/packet-filtering-firewalls/).
- [Docker Compose services](https://docs.docker.com/reference/compose-file/services/).
- [OpenSSH: ограничения authorized_keys](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT).
- [age: шифрование резервных копий](https://github.com/FiloSottile/age).

Локальные тесты проверяют управляющую логику с подменённым `awg`. Сборка образа,
создание интерфейса, NAT и реальное клиентское соединение проверяются отдельно на Linux VPS.
