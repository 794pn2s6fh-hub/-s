# worsewatched

SwiftUI-приложение для iPhone и Apple Watch. На главном экране находятся логи, контейнерные разделы и отдельный блок **Direct Paths**.

## Контейнеры

Через `pathleak` и `Worse Query` сканируются:

1. `/var/mobile/Containers/Data/Application` — Apps.
2. `/var/mobile/Containers/Data/PluginKitPlugin` — Plugins.
3. `/private/var/mobile/Containers/Shared/AppGroup` — Groups.
4. `/var/mobile/Containers/Data/InternalDaemon` — Daemons.
5. `/private/var/containers/Data/System` — System.
6. `/var/containers/Shared/SystemGroup` — SystemGroups.

Названия контейнеров берутся из `MCMMetadataIdentifier` в `.com.apple.mobile_container_manager.metadata.plist` или `com.apple.mobile_container_manager.metadata.plist`; предусмотрен fallback на MCM xattr. При открытии контейнера и его подпапок запрашивается отдельный Worse Query grant.

## Direct Paths

Следующие каталоги добавлены как экспериментальные прямые пути:

- `/System/Library`
- `/System/Cryptexes`
- `/System/Developer`
- `/Applications`
- `/usr/lib`
- `/usr/bin`

Для них не вызываются `pathleak`, `WorseQuery.grantAccess` или `WorseQuery.getAppGroupIdentifier`. Перечисление каталогов, переходы в подпапки и чтение файлов выполняются напрямую через файловые операции процесса. Символьные ссылки среди дочерних элементов не открываются как папки и не используются для чтения файлов.

Прямой режим намеренно не пытается обходить sandbox. Поэтому доступность каждого пути зависит от фактических прав процесса на устройстве: при отказе будет показана ошибка чтения, а не запущен Worse Query как fallback.

## Механизм контейнерного доступа

Используются Objective-C реализации `worse_query.m` и `pathleak.m` из предоставленного исходника Erosion. `pathleak` находит непосредственные дочерние пути через `fsgetpath`; затем Worse Query выдаёт sandbox extension для конкретного найденного каталога.

App Group не зашит в проект. Для контейнерных разделов перед сканированием читается entitlement `com.apple.security.application-groups` текущего процесса через `SecTaskCreateFromSelf` и `SecTaskCopyValueForEntitlement`, как в Erosion. Sideloader должен добавить собственную группу при переподписании приложения. Если entitlement отсутствует, контейнерное сканирование пропускается; Direct Paths продолжают проверяться независимо.

Запросы Worse Query сериализованы, потому что реализация временно использует `Library/Caches` текущей App Group для symlink. Для App Groups сохранена специальная обработка флага на iOS 26.

## Идентификаторы

- iPhone Bundle ID: `com.ceoca.worsewatch`
- Watch Bundle ID: `com.ceoca.worsewatch.watchkitapp`
- Display Name: `worsewatched`

## Сборка

GitHub Actions workflow `Build worsewatched IPA` собирает unsigned IPA. Ручная подпись через `ldid` не выполняется. Сборка требует macOS и Xcode.

## Ограничение проверки

Исходная реализация Worse Query рассчитана на iOS 26/27. Доступ к приватным `containermanager`/sandbox API и работу на watchOS нужно подтвердить на реальном устройстве. Прямые системные пути также требуют проверки на устройстве: успешное добавление пути в интерфейс не означает, что sandbox разрешит его чтение.

## Лицензия

Файл `Sources/Exploits/worse_query.m` сохранён из оригинальной реализации Worse Query (авторство Taj C / forcequit) и распространяется на условиях GNU GPL v3 or later. Текст лицензии приложен в `LICENSE-WORSE-QUERY`.
