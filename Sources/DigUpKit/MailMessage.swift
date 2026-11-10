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
/// are not parsed, nested multiparts go eight levels deep at most, and Mail.app's own
/// database is not read — issue #146's full Mail-source idea (Envelope Index,
/// `message://` opening, a Settings source toggle) is its own feature; this is the
/// file-reading slice, the one its "the same way it searches PDFs and documents" asks for.
///
/// The walk is over bytes, so charsets arrive intact: a body's bytes, once their
/// transfer encoding is decoded, are read in the charset the header declares — the
/// `iso-8859-1` and `windows-1252` families mail before ~2008 wrote (`8bit` bodies
/// among them, which a String-first walk lost: their high bytes were replacement
/// characters before the charset was ever read), RFC 2047 encoded-words read the charset
/// named inside them, and a header block that is not valid UTF-8 reads as Latin-1.
/// UTF-8 is the default and the fallback: the charsets mail has used by default since
/// then, and an undeclared body is read as UTF-8.
enum MailMessage {
    /// Search text for one message's bytes, nil when its shape is not understood.
    static func text(from data: Data) -> String? {
        guard data.count <= 8_000_000 else { return nil }   // a base64 vault isn't a mail to read
        return one(data, depth: 0)
    }

    /// One MIME block: its header block, then a body that is text, or a multipart of more blocks.
    private static func one(_ raw: Data, depth: Int) -> String? {
        guard depth <= 8,
              let split = raw.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) ?? raw.range(of: Data([0x0A, 0x0A]))
        else { return nil }
        let header = headerText(Data(raw[raw.startIndex..<split.lowerBound]))
        let body = Data(raw[split.upperBound...])   // the pieces are Data slices: the walk wants Data indices
        var lines: [String] = []
        for field in ["From", "To", "Cc", "Subject", "Date"] {
            for value in headerField(field, in: header) { lines.append("\(field): \(value)") }
        }
        let content = headerField("Content-Type", in: header).first?.lowercased() ?? "text/plain"
        let transfer = headerField("Content-Transfer-Encoding", in: header).first ?? "7bit"
        var out: [String] = [lines.joined(separator: "\n")]
        if content.contains("multipart") {
            guard let boundary = parameter("boundary", in: content) else { return nil }
            for chunk in parts(of: body, splitBy: "--\(boundary)") {
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

    /// The pieces of a body between `--boundary` markers. The closing marker needs no special case: what
    /// follows it carries no header/body split, so `one` answers nil for it and the piece drops. The scan
    /// is over bytes by hand: Foundation's `range(of:)` for Data has no window argument to search in.
    private static func parts(of body: Data, splitBy marker: String) -> [Data] {
        let bytes = [UInt8](body)
        let needle = [UInt8](marker.utf8)
        guard !needle.isEmpty else { return [body] }
        func next(from: Int) -> Int? {
            var at = from
            while at + needle.count <= bytes.count {
                if bytes[at] == needle[0], Array(bytes[at..<at + needle.count]) == needle { return at }
                at += 1
            }
            return nil
        }
        var out: [Data] = []
        var start = 0
        while let found = next(from: start) {
            out.append(Data(bytes[start..<found]))
            start = found + needle.count
        }
        out.append(Data(bytes[start...]))
        return out
    }

    /// The header block as text: UTF-8 when its bytes are valid UTF-8 (the shape modern mail writes raw),
    /// Latin-1 when they are not (the shape mail before ~2008 wrote): the replacement character is never
    /// a header, and a French subject spelled `café` in a header stays a word search finds.
    private static func headerText(_ block: Data) -> String {
        String(bytes: block, encoding: .utf8) ?? decoded([UInt8](block), "iso-8859-1")
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
    /// Apple Mail and Outlook Express wrote by default. Any other declared charset reads as UTF-8.
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

    private static func decode(_ body: Data, _ transfer: String, _ contentType: String) -> String {
        let charset = parameter("charset", in: contentType)
        // 7bit, 8bit, binary — the bytes as they are, in the declared charset. An `8bit` body of an
        // older mail is the shape this fixes: the high bytes reach here intact.
        var text = decoded([UInt8](body), charset)
        switch transfer.lowercased() {
        case "quoted-printable", "quoted_printable": text = quotedPrintable([UInt8](body), charset)
        case "base64":
            var clean: [UInt8] = []
            clean.reserveCapacity(body.count + 3)
            for byte in body where byte != 0x0A && byte != 0x0D { clean.append(byte) }   // mail wraps it
            while clean.count % 4 != 0 { clean.append(0x3D) }   // RFC 2047 sends 7-bit words unpadded
            // A body that isn't base64 at all stays what its bytes spell — better search text than the
            // base64 letters, which is what the fallback of old handed to the index.
            if let data = Data(base64Encoded: Data(clean), options: [.ignoreUnknownCharacters]) {
                text = decoded([UInt8](data), charset)
            }
        default: break
        }
        if contentType.contains("html") { text = DocExtractor.plainText(fromHTML: text) }
        return text
    }

    /// `=3D` hex escapes and `=\r\n` soft line breaks (RFC 2045) — collected as bytes and read back in
    /// the declared charset (UTF-8 when the header names none) at the end, so `=C3=A9` lands as "é" and
    /// `=E9` under `charset=iso-8859-1` lands as "é" too. Plain text (the run between escapes, and a
    /// hex-looking word after an unescaped `=`) passes through as written. One linear walk over the
    /// bytes: rebuilding the rest per escape made the String version quadratic (measured at the review:
    /// 128k escapes, 76 s on this box), and a body of dense escapes at the 8 MB cap must cost one pass.
    static func quotedPrintable(_ raw: [UInt8], _ charset: String? = nil) -> String {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(raw.count)
        var at = 0
        while at < raw.count {
            let byte = raw[at]
            guard byte == 0x3D else { bytes.append(byte); at += 1; continue }
            guard at + 1 < raw.count else { bytes.append(0x3D); at += 1; continue }   // `=` ends the body
            let next = raw[at + 1]
            if next == 0x0A { at += 2; continue }   // soft break: the line ended at the `=`
            if next == 0x0D {                       // a CRLF pair is one break, a lone CR breaks on its own
                at += (at + 2 < raw.count && raw[at + 2] == 0x0A) ? 3 : 2
                continue
            }
            if at + 2 < raw.count, let hex = hexByte(high: next, low: raw[at + 2]) {
                bytes.append(hex)
                at += 3
                continue
            }
            bytes.append(0x3D)   // a stray "=" is mail being generous: keep it
            at += 1
        }
        return decoded(bytes, charset)
    }

    /// RFC 2045's two hex digits as one byte. Mail writes them uppercase; it has been generous about
    /// case since then, so both spellings decode.
    private static func hexByte(high: UInt8, low: UInt8) -> UInt8? {
        func digit(_ byte: UInt8) -> UInt8? {
            switch byte {
            case 0x30...0x39: return byte - 0x30
            case 0x41...0x46: return byte - 0x41 + 10
            case 0x61...0x66: return byte - 0x61 + 10
            default: return nil
            }
        }
        guard let top = digit(high), let low = digit(low) else { return nil }
        return top &* 16 &+ low   // 15×16+15 = 255: the product never leaves a byte
    }
}
