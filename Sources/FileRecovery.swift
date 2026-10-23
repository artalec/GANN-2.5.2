import Foundation

/// Поиск пропавшего файла трека по всему компьютеру.
///
/// Порядок: сначала Spotlight (быстро, если индекс включён), затем полный обход
/// от корня диска с пропуском системных каталогов. Совпадением считаются имя,
/// размер и SHA-256. Каждый шаг пишется в журнал с префиксом "DJPlayer recovery:".
enum FileRecovery {

    struct Match {
        let url: URL
        let fingerprint: FileFingerprint
    }

    static func log(_ message: String) {
        NSLog("DJPlayer recovery: %@", message)
    }

    /// macOS может хранить одно и то же имя в разных Unicode-формах (кириллица, «й», «ё»).
    /// Сравниваем в одной форме, иначе одинаковые на вид имена не совпадут.
    static func normalized(_ s: String) -> String {
        s.precomposedStringWithCanonicalMapping
    }

    /// Системные каталоги, в которых пользовательских файлов нет.
    /// Префикс "/Library/" — только системная библиотека (верхний уровень).
    /// Пользовательская ~/Library НЕ пропускается: там лежит iCloud Drive.
    private static let systemPrefixes = [
        "/System/", "/private/", "/usr/", "/bin/", "/sbin/", "/dev/", "/cores/", "/var/", "/Library/"
    ]

    /// Служебные места, которые пропускаем на любом уровне.
    private static let skippedFragments = [
        "/.Trash/", "/Backups.backupdb/", "/node_modules/", "/.git/", "/Library/Caches/"
    ]

    private static func skipped(_ path: String) -> Bool {
        if systemPrefixes.contains(where: { path.hasPrefix($0) }) { return true }
        return skippedFragments.contains(where: { path.contains($0) })
    }

    /// Считает каталоги, к которым нет доступа. Без этого отказ macOS выглядит
    /// как «файла нет», и причину не видно.
    private final class DeniedCounter {
        private(set) var count = 0
        private(set) var samples: [String] = []
        func add(_ path: String) {
            count += 1
            if samples.count < 3 { samples.append(path) }
        }
    }

    static func find(name: String, size: Int64, hash: String, excluding oldPath: String) -> Match? {
        let started = Date()
        let target = normalized(name)

        // 1. Spotlight: быстро, если индекс включён.
        let spot = spotlightMatches(name: name)
        log("Spotlight: кандидатов по имени «\(name)» — \(spot.count)")
        if let m = check(spot, target: target, size: size, hash: hash, excluding: oldPath) {
            return m
        }

        // 2. Полный обход от корня. Работает и без индекса.
        let denied = DeniedCounter()
        guard let en = FileManager.default.enumerator(
            at: URL(fileURLWithPath: "/"),
            includingPropertiesForKeys: [.isSymbolicLinkKey],
            options: [.skipsPackageDescendants],
            errorHandler: { url, _ in
                denied.add(url.path)
                return true      // продолжаем обход, отказ не останавливает поиск
            }
        ) else {
            log("обход: не удалось открыть корень диска")
            return nil
        }

        var walked = 0
        var candidates: [URL] = []
        for case let url as URL in en {
            let path = url.path
            if skipped(path) { en.skipDescendants(); continue }
            if (try? url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true { continue }
            walked += 1
            if normalized(url.lastPathComponent) == target {
                candidates.append(url)
            }
        }
        let seconds = Date().timeIntervalSince(started)
        log("обход: просмотрено \(walked) элементов за \(String(format: "%.1f", seconds)) с, совпало по имени — \(candidates.count)")

        if denied.count > 0 {
            log("обход: нет доступа к \(denied.count) каталогам, например: \(denied.samples.joined(separator: ", ")). "
                + "Выдайте полный доступ к диску: Системные настройки → Конфиденциальность и безопасность → "
                + "Полный доступ к диску → добавьте Терминал (или DJPlayer), затем перезапустите приложение.")
        }

        return check(candidates, target: target, size: size, hash: hash, excluding: oldPath)
    }

    /// Проверяет кандидатов: имя → размер → хэш. Хэш считаем только при совпадении размера.
    private static func check(_ urls: [URL], target: String, size: Int64, hash: String,
                              excluding oldPath: String) -> Match? {
        for url in urls {
            guard url.path != oldPath, normalized(url.lastPathComponent) == target else { continue }
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
                  let s = attrs[.size] as? NSNumber else {
                log("«\(url.path)»: нет доступа к атрибутам файла")
                continue
            }
            guard s.int64Value == size else {
                log("«\(url.path)»: размер другой (\(s.int64Value) ≠ \(size)) — пропуск")
                continue
            }
            guard let fp = FileFingerprint.compute(path: url.path) else {
                log("«\(url.path)»: не удалось прочитать файл")
                continue
            }
            if fp.sha256 == hash {
                log("совпадение по хэшу: \(url.path)")
                return Match(url: url, fingerprint: fp)
            }
            log("«\(url.path)»: размер совпал, хэш другой — это не та копия")
        }
        return nil
    }

    /// Кандидаты по имени через Spotlight. Ошибки пишем в журнал, а не глотаем.
    private static func spotlightMatches(name: String) -> [URL] {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/mdfind")
        p.arguments = ["-name", name]
        let out = Pipe()
        let err = Pipe()
        p.standardOutput = out
        p.standardError = err
        do {
            try p.run()
        } catch {
            log("mdfind не запустился: \(error.localizedDescription)")
            return []
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        if p.terminationStatus != 0 {
            log("mdfind завершился с кодом \(p.terminationStatus): \(String(decoding: errData, as: UTF8.self))")
        }
        return String(decoding: data, as: UTF8.self)
            .split(separator: "\n")
            .map { URL(fileURLWithPath: String($0)) }
    }
}
