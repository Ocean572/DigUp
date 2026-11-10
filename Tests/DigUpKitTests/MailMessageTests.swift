import Foundation
import Testing
@testable import DigUpKit

/// Issue #146, the file-reading slice: Apple Mail's `.emlx` as searchable text —
/// header lines, quoted-printable and base64 bodies, HTML stripped, RFC 2047 encoded
/// words, multipart nesting, attachments left out. Built from bytes here (no fixtures,
/// no Mail.app): the shapes real .emlx files carry, as Apple's Mail writes them.
@Suite struct MailMessageTests {
    func bytes(_ s: String) -> Data { Data(s.utf8) }

    @Test func plainMessageGivesItsHeaderLinesThenItsBody() throws {
        let mail = "From: Ana <ana@example.org>\r\n"
            + "To: Bo <bo@example.org>\r\n"
            + "Subject: The bridge survey\r\n"
            + "Date: Tue, 4 Nov 2025 09:12:00 +0100\r\n"
            + "Content-Type: text/plain; charset=utf-8\r\n"
            + "\r\n"
            + "The ferry timetables change with the tide.\r\n"
            + "Bring the survey flags on Saturday.\r\n"
        let text = try #require(MailMessage.text(from: bytes(mail)))
        #expect(text.contains("Subject: The bridge survey"))
        #expect(text.contains("From: Ana <ana@example.org>"))
        #expect(text.contains("ferry timetables"))
        #expect(text.contains("survey flags"))
    }

    @Test func quotedPrintableAndSoftBreaksAreDecoded() throws {
        let mail = "Subject: =?utf-8?Q?Copied=5FPath?=\r\n"
            + "Content-Type: text/plain; charset=utf-8\r\n"
            + "Content-Transfer-Encoding: quoted-printable\r\n"
            + "\r\n"
            + "A =3D sign, a =C3=A9 accent, and a soft=\r\n"
            + "broken line.\r\n"
        let text = try #require(MailMessage.text(from: bytes(mail)))
        #expect(text.contains("Copied_Path"))
        #expect(text.contains("A = sign"))
        #expect(text.contains("é accent"))
        #expect(text.contains("a softbroken line.") || text.contains("a soft broken line."))
    }

    @Test func htmlBodiesAreStripped() throws {
        let mail = "Subject: Notes\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
            + "<html><body><style>p{}</style><p>The millrace <b>freezes</b> at the edges.</p>"
            + "<script>var x=1;</script></body></html>\r\n"
        let text = try #require(MailMessage.text(from: bytes(mail)))
        #expect(text.contains("The millrace freezes at the edges."))
        #expect(!text.contains("<b>"))
        #expect(!text.contains("var x"))
    }

    @Test func base64BodyDecodes() throws {
        let body = Data("The lighthouse keeper climbed the stairs.".utf8).base64EncodedString()
        let mail = "Subject: Late note\r\nContent-Type: text/plain\r\n"
            + "Content-Transfer-Encoding: base64\r\n\r\n" + body + "\r\n"
        let text = try #require(MailMessage.text(from: bytes(mail)))
        #expect(text.contains("lighthouse keeper climbed"))
    }

    /// The charsets mail before ~2008 wrote: `quoted-printable` with `charset=iso-8859-1` (Apple Mail's
    /// and Outlook Express's default), base64 with the same, and `windows-1252`, whose 0x80…0x9F is not
    /// Latin-1's. Their high bytes read as UTF-8 arrive as the replacement character, so an accented
    /// word becomes a word keyword search cannot find — the shape issue #146's review (2026-11-10) found
    /// in this reader.
    @Test func declaredCharsetsReadTheirOwnBytes() throws {
        let mail = "Subject: =?iso-8859-1?Q?Le_caf=E9?=\r\n"
            + "Content-Type: text/plain; charset=iso-8859-1\r\n"
            + "Content-Transfer-Encoding: quoted-printable\r\n"
            + "\r\n"
            + "Le caf=E9 au lait, et un th=E9.\r\n"
        let text = try #require(MailMessage.text(from: bytes(mail)))
        #expect(text.contains("Le café au lait, et un thé."))
        #expect(text.contains("Subject: Le café"))     // the encoded-word header reads its own charset
        #expect(!text.contains("\u{FFFD}"))
        let win = "Subject: 1252\r\nContent-Type: text/plain; charset=windows-1252\r\n"
            + "Content-Transfer-Encoding: quoted-printable\r\n\r\nThe =93bridge=94 cost =80 tokens.\r\n"
        #expect(try #require(MailMessage.text(from: bytes(win))).contains("The “bridge” cost € tokens."))
        let latin1 = Data([0x63, 0x61, 0x66, 0xE9]).base64EncodedString()   // "café" spelled in Latin-1
        let b64 = "Subject: b64\r\nContent-Type: text/plain; charset=iso-8859-1\r\n"
            + "Content-Transfer-Encoding: base64\r\n\r\n" + latin1 + "\r\n"
        #expect(try #require(MailMessage.text(from: bytes(b64))).contains("café"))
        // the table, directly: 0x80…0x9F is the half 1252 moves, 0xA0…0xFF is Latin-1's, and an
        // undeclared body stays UTF-8 — the documented default, replacement character and all
        #expect(MailMessage.decoded([0x63, 0x61, 0x66, 0xE9], "ISO_8859-1:1987") == "café")
        #expect(MailMessage.decoded([0x80, 0x92, 0xA3], "windows-1252") == "€’£")
        #expect(MailMessage.decoded([0x63, 0x61, 0x66, 0xE9], nil) == "caf\u{FFFD}")
        #expect(MailMessage.decoded([0x63, 0x61, 0x66, 0xE9], "utf-8") == "caf\u{FFFD}")
        #expect(MailMessage.decoded([0x63, 0x61, 0x66, 0xC3, 0xA9], "utf-8") == "café")
    }

    /// Issue #146's review (2026-11-10), the reason the walk is over bytes: an `8bit` body in
    /// `iso-8859-1` — the shape Outlook Express and Mail.app of that era wrote — carries its accented
    /// letters as raw high bytes. Reading the file as text first turned every one of them into the
    /// replacement character before the charset was ever read. They arrive intact now.
    @Test func an8BitBodyInLatin1KeepsItsAccents() throws {
        var mail = Data("From: Ana <ana@example.org>\r\nSubject: =?iso-8859-1?Q?Le_caf=E9?=\r\n".utf8)
        mail.append(Data(("Content-Type: text/plain; charset=iso-8859-1\r\n"
            + "Content-Transfer-Encoding: 8bit\r\n\r\nLe caf").utf8))
        mail.append(0xE9)
        mail.append(Data(" au lait, et un th".utf8))
        mail.append(0xE9)
        mail.append(Data(".\r\n".utf8))
        let text = try #require(MailMessage.text(from: mail))
        #expect(text.contains("Le café au lait, et un thé."))
        #expect(text.contains("Subject: Le café"))
        #expect(!text.contains("\u{FFFD}"))
    }

    /// A header block spelled in raw Latin-1 (`Subject: Le café`, no encoded-word — the shape mail of
    /// that era wrote): valid UTF-8 stays UTF-8, and a block that is not reads as Latin-1. The
    /// replacement character is never a header.
    @Test func aHeaderBlockInRawLatin1ReadsAsLatin1() throws {
        var mail = Data("From: Ana <ana@example.org>\r\nSubject: Le caf".utf8)
        mail.append(0xE9)
        mail.append(Data("\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThe bridge survey.\r\n".utf8))
        let text = try #require(MailMessage.text(from: mail))
        #expect(text.contains("Subject: Le café"))
        #expect(text.contains("The bridge survey."))
        #expect(!text.contains("\u{FFFD}"))
    }

    @Test func attachmentsStayOutAndTheHeaderStaysSearchable() throws {
        let png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).base64EncodedString()
        let mail = "From: Ana <ana@example.org>\r\nSubject: The violin varnish\r\n"
            + "Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n"
            + "--b1\r\nContent-Type: text/plain\r\n\r\nThe varnish coat dries by afternoon.\r\n"
            + "--b1\r\nContent-Type: image/png; name=coat.png\r\n"
            + "Content-Transfer-Encoding: base64\r\n\r\n\(png)\r\n--b1--\r\n"
        let text = try #require(MailMessage.text(from: bytes(mail)))
        #expect(text.contains("Subject: The violin varnish"))
        #expect(text.contains("varnish coat dries"))
        #expect(!text.contains(png))   // the attachment's bytes are not the message's words
    }

    @Test func attachmentOnlyMessagesKeepTheirHeaderLines() throws {
        let png = Data([0x89, 0x50, 0x4E, 0x47]).base64EncodedString()
        let mail = "From: Ana <ana@example.org>\r\nSubject: The scan\r\n"
            + "Content-Type: image/png; name=scan.png\r\nContent-Transfer-Encoding: base64\r\n\r\n\(png)\r\n"
        let text = try #require(MailMessage.text(from: bytes(mail)))
        #expect(text.contains("Subject: The scan"))
        #expect(!text.contains(png))
    }

    @Test func nestedMultipartNests() throws {
        let mail = "Subject: Layers\r\nContent-Type: multipart/alternative; boundary=\"outer\"\r\n\r\n"
            + "--outer\r\nContent-Type: text/plain\r\n\r\nPlain words: the compost and straw.\r\n"
            + "--outer\r\nContent-Type: multipart/related; boundary=\"inner\"\r\n\r\n"
            + "--inner\r\nContent-Type: text/html\r\n\r\n<p>Rich words: the patient gardener.</p>\r\n"
            + "--inner--\r\n--outer--\r\n"
        let text = try #require(MailMessage.text(from: bytes(mail)))
        #expect(text.contains("compost and straw"))
        #expect(text.contains("patient gardener"))
    }

    @Test func encodedWordsInHeadersDecode() {
        #expect(MailMessage.decodedHeader("=?utf-8?B?QnJpZQ?= =?utf-8?Q?and?= jam") == "Brie and jam")
        #expect(MailMessage.decodedHeader("plain, no words") == "plain, no words")
        // hex escapes and `_` spaces in one word — the earlier marker wins, and the
        // word decodes fully: Apple Mail writes subjects like this one.
        #expect(MailMessage.decodedHeader("=?utf-8?Q?R=C3=A9_Erde?=") == "Ré Erde")
    }

    @Test func charsetNamesThatShrinkWhenLoweredDoNotTrap() throws {
        // Slicing the value with indices from value.lowercased() traps (fatal, not a
        // catchable Error — the whole helper would die) when lowering changes UTF-8
        // length: `İ` is 2 bytes, its lower case 3. Mail headers are untrusted input.
        let mail = "Content-Type: text/plain; charset=İso-8859-1\r\n\r\nWords about the quays.\r\n"
        let text = MailMessage.text(from: bytes(mail))
        #expect(text == nil || text!.contains("Words about the quays"))
        #expect(MailMessage.parameter("boundary", in: "multipart/mixed; boundary=\"İzmir\"") == "İzmir")
        #expect(MailMessage.parameter("CHARSET", in: "text/plain; Charset=UTF-8") == "UTF-8")
    }

    @Test func quotedBoundariesAreHonored() {
        #expect(MailMessage.parameter("boundary", in: "multipart/mixed; boundary=\"x;1\"") == "x;1")
        #expect(MailMessage.parameter("boundary", in: "multipart/mixed; boundary=abc123") == "abc123")
        #expect(MailMessage.parameter("charset", in: "text/plain; charset=utf-8") == "utf-8")
    }

    @Test func shapesTheReaderDoesNotUnderstandFallBackToRawText() throws {
        // No header/body split at all: the caller (`DocExtractor`) keeps the raw text.
        #expect(MailMessage.text(from: bytes("just one line, no blank line")) == nil)
    }

    @Test func emlxIsADocExtension() {
        #expect(Rules.docExtensions.contains("emlx"))
    }
}
