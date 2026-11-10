import Foundation

/// Apple Mail's messages (`.emlx`) read for search: the sender, recipient, subject and
/// date header lines first, then the body — `text/*` parts as they are, `text/html`
/// stripped, quoted-printable and base64 transfer encodings decoded, attachments left
/// out (the files beside them are indexed by their own readers; a message whose only
/// body is an attachment keeps its header lines, which is the searchable part of it).
///
/// Deliberately small: RFC 822 is wide, and a file this reader can't make sense of
/// answers `nil` — `DocExtractor` then returns the raw text, which for mail is mostly
/// readable words and never less than what people get today by treating the file as
/// text. It is *not* a mail client: attachments are not unpacked, DKIM and MIME quirks
/// are not parsed, nested multiparts go eight levels deep at most. Charsets: a body's or
/// an encoded-word's bytes, once their transfer encoding is decoded, are read in the
/// charset the header declares for the `iso-8859-1` and `windows-1252` families mail
/// before ~2008 sends, and as UTF-8 for everything else — the file's own bytes are
/// UTF-8-decoded first, so an `8bit` body in another charset is the documented limit.
/// Mail.app's own database is not read — issue #146's
/// full Mail-source idea (Envelope Index, `message://` opening, a Settings source
/// toggle) is its own feature; this is the file-reading slice, the one its "the same way
/// it searches PDFs and documents" asks for.
enum MailMessage {
    /// Search text for one message's bytes, nil when its shape is not understood.
    static func text(from data: Data) -> String? {
        guard data.count <= 8_000_000 else { return nil }   // a base64 vault isn't a mail to read
        return one(String(decoding: data, as: UTF8.self), depth: 0)
    }

    private static func one(_ raw: String, depth: Int) -> String? {
        guard depth <= 8, let split = raw.firstRange(of: "\r\n\r\n") ?? raw.firstRange(of: "\n\n") else { return nil }
        let header = String(raw[raw.startIndex..<split.lowerBound])
        let body = String(raw[split.upperBound...])
        var lines: [String] = []
        for field in ["From", "To", "Cc", "Subject", "Date"] {
            for value in headerField(field, in: header) { lines.append("\(field): \(value)") }
        }
        let content = headerField("Content-Type", in: header).first?.lowercased() ?? "text/plain"
        let transfer = headerField("Content-Transfer-Encoding", in: header).first ?? "7bit"
        var out: [String] = [lines.joined(separator: "\n")]
        if content.contains("multipart") {
            guard let boundary = parameter("boundary", in: content) else { return nil }
            for chunk in body.components(separatedBy: "--\(boundary)") {
                guard let part = one(chunk, depth: depth + 1) else { continue }
                out.append(part)
            }
        } else if content.hasPrefix("text/") {
            out.append(decode(body, transfer, content))
        }   // an attachment's bytes: the header lines above are all it offers to a text index
        let text = out.filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            .joined(separator: "\n\n")
        return text.isEmpty ? nil : text
    }

    // MARK: Headers

    /// Values of a header field: continuation lines (the ones starting with a space) joined,
    /// RFC 2047 encoded-words decoded — the shape mail has used since 1997.
    static func headerField(_ name: String, in header: String) -> [String] {
        let normalized = header.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
        var out: [String] = []
        var current = ""
        var collecting = false
        for line in normalized.components(separatedBy: "\n") {
            if line.isEmpty { continue }
            if line.first == " " || line.first == "\t" {
                if collecting { current += " " + line.trimmingCharacters(in: .whitespaces) }
                continue
            }
            if collecting, !current.isEmpty { out.append(decodedHeader(current)) }
            collecting = false
            guard let colon = line.firstIndex(of: ":") else { continue }
            guard line[line.startIndex..<colon].trimmingCharacters(in: .whitespaces)
                    .caseInsensitiveCompare(name) == .orderedSame
            else { continue }
            collecting = true
            current = String(line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces))
        }
        if collecting, !current.isEmpty { out.append(decodedHeader(current)) }
        return out
    }

    /// "=?utf-8?Q?Copied=5FPath?=" → "Copied_Path"-style words, `B` base64 and `Q`
    /// quoted-printable (where `_` is the space). An undecodable word stays as
    /// written: mail readers are generous, and a literal is better search text than
    /// dropping the line.
    static func decodedHeader(_ value: String) -> String {
        var out = ""
        var rest = Substring(value)
        while let start = rest.firstRange(of: "=?") {
            out += rest[rest.startIndex..<start.lowerBound]
            let tail = rest[start.upperBound...]
            guard let end = tail.firstRange(of: "?=") else { out += rest[start.lowerBound...]; return out }
            let words = String(tail[tail.startIndex..<end.lowerBound])
            rest = tail[end.upperBound...]
            let parts = words.split(separator: "?", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 3, let decoded = decodedHeaderWord(charset: parts[0], encoding: parts[1], text: parts[2]) else {
                out += "=\(words)?="
                continue
            }
            out += decoded
        }
        return out + String(rest)
    }

    /// One `=?charset?encoding?text?=` word. Its own header names the charset, so the bytes the
    /// `Q`/`B` encoding gives are read in it (issue #146's review, 2026-11-10: `=?iso-8859-1?Q?caf=E9?=`
    /// read as UTF-8 gives "caf\u{FFFD}", and a French subject loses its word to keyword search).
    private static func decodedHeaderWord(charset: String, encoding: String, text: String) -> String? {
        switch encoding.uppercased() {
        case "Q":
            var bytes: [UInt8] = []
            var rest = Substring(text)
            // the earlier of the next `_` (mail's space) and `=` (hex escape) — an
            // `=`-escape before a later `_` must not stop at the `_` with the raw
            // `=C3=A9` left in the text.
            while let at = [rest.firstIndex(of: "_"), rest.firstIndex(of: "=")].compactMap({ $0 }).min() {
                bytes.append(contentsOf: rest[rest.startIndex..<at].utf8)
                if rest[at] == "_" {
                    bytes.append(0x20)
                    rest = rest[rest.index(after: at)...]
                    continue
                }
                let after = rest[rest.index(after: at)...]
                guard after.count >= 2, let byte = UInt8(after.prefix(2), radix: 16) else { return nil }
                bytes.append(byte)
                rest = after.dropFirst(2)
            }
            bytes.append(contentsOf: rest.utf8)
            return decoded(bytes, charset)
        case "B":
            var word = text
            while word.count % 4 != 0 { word += "=" }   // RFC 2047 sends 7-bit words unpadded
            guard let data = Data(base64Encoded: word, options: [.ignoreUnknownCharacters]) else { return nil }
            return decoded([UInt8](data), charset)
        default:
            return nil
        }
    }

    /// The quoted string or bare token of a MIME parameter: `boundary="x;1"` → `x;1`.
    /// The case-insensitive search runs on the value *itself*: indices from
    /// `value.lowercased()` do not align when lowering changes a string's UTF-8 length
    /// (`İ` is 2 bytes, its lower case 3), and slicing the original with them is a
    /// fatal trap the callers cannot catch — mail headers are untrusted input.
    static func parameter(_ name: String, in value: String?) -> String? {
        guard let value else { return nil }
        guard let at = value.range(of: name + "=", options: [.caseInsensitive]) else { return nil }
        var tail = value[at.upperBound...]
        if tail.first == "\"" {
            tail = tail.dropFirst()
            guard let close = tail.firstIndex(of: "\"") else { return String(tail) }
            return String(tail[..<close])
        }
        return String(tail.prefix { !$0.isWhitespace && $0 != ";" && $0 != "," })
    }

    // MARK: Bodies

    /// The bytes of a decoded body (or of an RFC 2047 encoded-word) read in the charset its header
    /// declares. UTF-8 is the default and the fallback — `us-ascii`'s bytes are valid UTF-8, so it
    /// needs nothing. The two families mail before ~2008 sends are named here because reading their
    /// high bytes as UTF-8 gives the replacement character for every accented letter, and an accented
    /// word is a word keyword search cannot find: `charset=iso-8859-1` with `quoted-printable` is what
    /// Apple Mail and Outlook Express wrote by default. Any other declared charset reads as UTF-8, as
    /// the header of this file documents.
    static func decoded(_ bytes: [UInt8], _ charset: String?) -> String {
        switch charsetName(charset) {
        case "iso88591", "latin1":
            return String(decoding: bytes.map { UInt32($0) }, as: UTF32.self)   // every byte is its own code point
        case "windows1252", "cp1252", "1252":
            var units: [UInt32] = []
            units.reserveCapacity(bytes.count)
            for byte in bytes {
                units.append(byte < 0x80 ? UInt32(byte)
                    : byte < 0xA0 ? windows1252High[Int(byte) - 0x80]
                    : UInt32(byte))   // 0xA0…0xFF is Latin-1's own
            }
            return String(decoding: units, as: UTF32.self)
        default:
            return String(decoding: bytes, as: UTF8.self)
        }
    }

    /// `ISO-8859-1:1987` and `iso_8859-1` name the same charset as `iso-8859-1`: the name's first piece,
    /// letters and digits only, is what the switch above compares.
    private static func charsetName(_ charset: String?) -> String {
        guard let charset, let first = charset.split(separator: ":").first else { return "" }
        return String(first).lowercased().filter { $0.isLetter || $0.isNumber }
    }

    /// `windows-1252`'s high half, 0x80…0x9F as code points (its 0xA0…0xFF is Latin-1's own). The five
    /// slots the specification leaves undefined (0x81, 0x8D, 0x8F, 0x90, 0x9D) read as the replacement
    /// character. `UInt32` and not `Unicode.Scalar`: Swift gives the scalar no integer literal.
    private static let windows1252High: [UInt32] = [
        0x20AC, 0xFFFD, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,   // 0x80…0x87
        0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0xFFFD, 0x017D, 0xFFFD,   // 0x88…0x8F
        0xFFFD, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,   // 0x90…0x97
        0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0xFFFD, 0x017E, 0x0178,   // 0x98…0x9F
    ]

    private static func decode(_ body: String, _ transfer: String, _ contentType: String) -> String {
        let charset = parameter("charset", in: contentType)
        var text = body
        switch transfer.lowercased() {
        case "quoted-printable", "quoted_printable": text = quotedPrintable(body, charset)
        case "base64":
            var clean = body.filter { !$0.isNewline }
            while clean.count % 4 != 0 { clean += "=" }
            text = Data(base64Encoded: clean, options: [.ignoreUnknownCharacters])
                .map { decoded([UInt8]($0), charset) } ?? body
        default: break
        }
        if contentType.contains("html") { text = DocExtractor.plainText(fromHTML: text) }
        return text
    }

    /// `=3D` hex escapes and `=\r\n` soft line breaks (RFC 2045) — collected as bytes and
    /// read back in the declared charset (UTF-8 when the header names none) at the end, so `=C3=A9`
    /// lands as "é" and not as two letters, and `=E9` under `charset=iso-8859-1` lands as "é" too.
    /// Plain text (the run between escapes, and a hex-looking word after an unescaped
    /// `=`) passes through as written. The walk stays on views of the same string:
    /// rebuilding the rest per escape made it quadratic (measured at the review:
    /// 128k escapes, 76 s on this box) — a body of dense escapes at the 8 MB cap
    /// would take hours of one worker.
    static func quotedPrintable(_ text: String, _ charset: String? = nil) -> String {
        var bytes: [UInt8] = []
        var rest = Substring(text)
        while let at = rest.firstIndex(of: "=") {
            bytes.append(contentsOf: rest[rest.startIndex..<at].utf8)
            let after = rest[rest.index(after: at)...]
            if after.isEmpty { bytes.append(0x3D); return decoded(bytes, charset) }
            if after.first == "\n" || after.first == "\r" || after.first == "\r\n" {
                // Soft break: mail wraps long lines by ending them with "=". A CRLF pair is
                // one Character in Swift (grapheme), so all three shapes drop as one.
                rest = after.dropFirst(1)
                continue
            }
            let hex = after.prefix(2)
            if hex.count == 2, let byte = UInt8(hex, radix: 16) {   // not `after.count >= 2`:
                bytes.append(byte)                                    // Substring.count scans
                rest = after.dropFirst(2)                             // the whole rest — quadratic
                continue
            }
            bytes.append(0x3D)   // a stray "=" is mail being generous: keep it
            rest = after
        }
        bytes.append(contentsOf: rest.utf8)
        return decoded(bytes, charset)
    }
}
