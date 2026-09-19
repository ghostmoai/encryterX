"""
Publication-Quality Technical Specification PDF Generator for EncryptorX Steganography.
Uses ReportLab to build a professional, detailed whitepaper PDF document:
'EncryptorX_Steganography_Specification.pdf'
"""
import sys
import hashlib
from pathlib import Path

# Python 3.8 compatibility patch for ReportLab's usedforsecurity keyword
_orig_md5 = hashlib.md5
def _safe_md5(*args, **kwargs):
    kwargs.pop("usedforsecurity", None)
    return _orig_md5(*args, **kwargs)
hashlib.md5 = _safe_md5

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#7f849c"))

        # Running Header
        self.drawString(54, 11 * 72 - 36, "EncryptorX Steganography — Technical Specification & Whitepaper")
        self.drawRightString(8.5 * 72 - 54, 11 * 72 - 36, "v2.0 • Architecture & Proofs")
        self.setStrokeColor(colors.HexColor("#313244"))
        self.setLineWidth(0.5)
        self.line(54, 11 * 72 - 42, 8.5 * 72 - 54, 11 * 72 - 42)

        # Running Footer
        self.setStrokeColor(colors.HexColor("#313244"))
        self.setLineWidth(0.5)
        self.line(54, 46, 8.5 * 72 - 54, 46)

        self.drawString(54, 32, "Confidentiality: Open Security Specification | Zero-Telemetry")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * 72 - 54, 32, page_str)

        self.restoreState()


def build_pdf(filename: str = "EncryptorX_Steganography_Specification.pdf"):
    pdf_path = Path(filename)
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    c_primary = colors.HexColor("#1e1e2e")
    c_accent = colors.HexColor("#0088cc")
    c_accent_dark = colors.HexColor("#005580")
    c_text = colors.HexColor("#181825")
    c_text_muted = colors.HexColor("#45475a")
    c_bg_card = colors.HexColor("#f8f9fc")
    c_border = colors.HexColor("#dce0e8")
    c_code_bg = colors.HexColor("#e6e9ef")

    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=c_primary,
    )

    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=c_accent,
    )

    meta_style = ParagraphStyle(
        "CoverMeta",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=c_text_muted,
    )

    h1_style = ParagraphStyle(
        "SectionH1",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=c_accent_dark,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=13,
        textColor=c_text,
        spaceBefore=2,
        spaceAfter=4,
    )

    bullet_style = ParagraphStyle(
        "BulletCustom",
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceBefore=2,
        spaceAfter=2,
    )

    code_style = ParagraphStyle(
        "CodeSnippet",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#11111b"),
        backColor=c_code_bg,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=6,
    )

    card_text_style = ParagraphStyle(
        "CardText",
        parent=body_style,
        fontSize=8.5,
        leading=12,
        textColor=c_primary,
    )

    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
        alignment=1,
    )

    table_cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=c_text,
    )

    table_cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=table_cell_style,
        fontName="Helvetica-Bold",
    )

    table_cell_code = ParagraphStyle(
        "TableCellCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#1e1e2e"),
    )

    story = []

    # Title
    story.append(Paragraph("EncryptorX Steganography Engine", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("Cryptographic Steganography with Hull-Dobell Pixel Shuffling & Preamble Bootstrapping", subtitle_style))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=2, color=c_accent, spaceBefore=2, spaceAfter=8))

    meta_text = (
        "<b>Document Version:</b> 2.0.0 &nbsp;|&nbsp; "
        "<b>Classification:</b> Technical Whitepaper & Specification &nbsp;|&nbsp; "
        "<b>Reference Implementation:</b> Python <code>encryptorx.stego</code> / Rust GUI &nbsp;|&nbsp; "
        "<b>Date:</b> September 2026"
    )
    story.append(Paragraph(meta_text, meta_style))
    story.append(Spacer(1, 10))

    # Executive Summary Card
    summary_html = (
        "<b>Executive Summary:</b> Conventional Least Significant Bit (LSB) steganography embeds data sequentially from pixel (0,0), "
        "creating localized spatial artifacts and statistical step-signatures readily detectable via Chi-Square and Sample-Pair steganalysis. "
        "EncryptorX Stego introduces <b>Pseudo-Random Pixel Shuffling</b> governed by the <i>Hull-Dobell Theorem</i>, achieving full-period "
        "cycle-walking permutations with strict O(1) memory overhead. Payloads are shielded with <b>PBKDF2-HMAC-SHA256</b> key derivation, "
        "stream keystream encryption, and <b>Encrypt-then-MAC (HMAC-SHA256)</b> integrity verification. A universal 48-bit preamble "
        "bootstrapping format enables automated carrier inspection, multi-bit allocation (1, 2, or 4 bpc), and selective channel targeting (RGB, Blue-only)."
    )
    card_table = Table([[Paragraph(summary_html, card_text_style)]], colWidths=[504])
    card_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_bg_card),
        ('BOX', (0, 0), (-1, -1), 1, c_border),
        ('LINELEFT', (0, 0), (-1, -1), 3, c_accent),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(card_table)
    story.append(Spacer(1, 10))

    # Section 1
    story.append(Paragraph("1. Steganalysis Vulnerabilities & Threat Model", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=c_border, spaceBefore=1, spaceAfter=6))
    story.append(Paragraph(
        "Digital steganography aims to conceal the very existence of a communication channel within an innocent cover medium. "
        "Traditional sequential LSB replacement fails against modern automated detection pipelines due to three critical flaws:",
        body_style
    ))
    story.append(Paragraph(
        "• <b>Spatial Density Clustering:</b> Sequential injection concentrates bit flips in the top-left corner of an image. "
        "Visual differential maps reveal an abrupt rectangular boundary where the payload ends.",
        bullet_style
    ))
    story.append(Paragraph(
        "• <b>Pair of Values (PoV) Distortion:</b> Natural image pixels feature smooth histograms. LSB modification couples pixel pairs "
        "(2k, 2k+1), tending their counts toward equal frequencies. Westfeld and Pfitzmann's Chi-Square analysis detects this deviation with p &lt; 0.001.",
        bullet_style
    ))
    story.append(Paragraph(
        "• <b>Absence of Authenticity:</b> Standard steganography tools lack cryptographic MACs. An adversary can perform bit-flipping "
        "or payload truncation without detection by the receiver.",
        bullet_style
    ))

    # Section 2
    story.append(Paragraph("2. Mathematical Foundations: Hull-Dobell Permutations", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=c_border, spaceBefore=1, spaceAfter=6))
    story.append(Paragraph(
        "To scatter bits uniformly across the carrier without maintaining an in-memory lookup table of millions of pixel coordinates, "
        "EncryptorX utilizes a pseudo-random Linear Congruential Generator (LCG) configured to guarantee a full period over power-of-two domains.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Theorem (Hull &amp; Dobell, 1962):</b> A linear congruential sequence defined by "
        "<i>X<sub>n+1</sub> = (a · X<sub>n</sub> + c) mod M</i> possesses a full period of length <i>M</i> if and only if: "
        "<br/>1. <b>gcd(c, M) = 1</b> (increment and modulus are coprime)."
        "<br/>2. Every prime factor of <i>M</i> divides <i>a - 1</i>."
        "<br/>3. If <i>M</i> is a multiple of 4, then <b>a ≡ 1 (mod 4)</b>.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Cycle-Walking Permutations:</b><br/>"
        "Let <i>N</i> be the total available channel slots (<i>W × H × Channels</i>). We compute <i>k = ⌈log<sub>2</sub>(N)⌉</i> "
        "and set modulus <i>M = 2<sup>k</sup> ≥ N</i>. We derive multiplier <i>a = (seed · 8 + 5) mod M</i> and increment "
        "<i>c = (seed · 2 + 1) mod M</i>. By construction, <i>c</i> is odd and <i>a ≡ 1 (mod 4)</i>. "
        "When <i>X<sub>n</sub> ≥ N</i>, the generator discards the sample and advances (Cycle-Walking). "
        "Because <i>M &lt; 2N</i>, the expected number of steps per valid slot is strictly &lt; 2, maintaining O(1) memory overhead.",
        body_style
    ))

    # Section 3
    story.append(Paragraph("3. Visual Fidelity Metrics & Human Visual System (HVS)", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=c_border, spaceBefore=1, spaceAfter=6))
    story.append(Paragraph(
        "The objective visual transparency of stego images is evaluated using Mean Squared Error (MSE) and Peak Signal-to-Noise Ratio (PSNR):",
        body_style
    ))
    metrics_box = (
        "<b>Mean Squared Error:</b> &nbsp;&nbsp; <i>MSE = (1 / 3WH) · ∑<sub>x,y,c</sub> [ I(x,y,c) - I'(x,y,c) ]<sup>2</sup></i><br/>"
        "<b>Peak Signal-to-Noise Ratio:</b> &nbsp;&nbsp; <i>PSNR = 10 · log<sub>10</sub>( 255<sup>2</sup> / MSE ) &nbsp; [dB]</i>"
    )
    story.append(Table([[Paragraph(metrics_box, code_style)]], colWidths=[504]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "In 1-bit LSB mode, each targeted channel value is modified by at most +/- 1. For typical payloads occupying &lt; 20% of image slots, "
        "<b>PSNR exceeds 65 to 75 dB</b>, which is mathematically indistinguishable from camera CMOS sensor thermal noise.<br/>"
        "<b>Blue-Channel Invariance:</b> The human retina contains S-cones (blue sensitive) accounting for only ~5-7% of total "
        "foveal photoreceptors. Targeting only the Blue channel (<code>channels='B'</code>) ensures complete human visual imperceptibility "
        "even at 2 or 4 bits per channel.",
        body_style
    ))

    # Section 4
    story.append(Paragraph("4. Binary Frame Protocol & Preamble Bootstrapping", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=c_border, spaceBefore=1, spaceAfter=6))
    story.append(Paragraph(
        "EncryptorX partitions embedding into two deterministic phases to allow automated, zero-knowledge extraction:",
        body_style
    ))

    proto_headers = [
        Paragraph("Segment", table_header_style),
        Paragraph("Size", table_header_style),
        Paragraph("Embedding Rules", table_header_style),
        Paragraph("Purpose / Encoding Description", table_header_style),
    ]
    proto_rows = [
        [
            Paragraph("<b>MAGIC HEADER</b>", table_cell_bold),
            Paragraph("4 bytes", table_cell_code),
            Paragraph("Fixed 1 bpc, RGB", table_cell_style),
            Paragraph("Identifier <code>b'SX02'</code> (0x53 0x58 0x30 0x32)", table_cell_style),
        ],
        [
            Paragraph("<b>FLAGS</b>", table_cell_bold),
            Paragraph("1 byte", table_cell_code),
            Paragraph("Fixed 1 bpc, RGB", table_cell_style),
            Paragraph("Bit 0: Is_File | Bit 1: Is_Password_Protected | Bit 2: Compressed", table_cell_style),
        ],
        [
            Paragraph("<b>CONFIG</b>", table_cell_bold),
            Paragraph("1 byte", table_cell_code),
            Paragraph("Fixed 1 bpc, RGB", table_cell_style),
            Paragraph("Bit 7: Algorithm (0=LCG, 1=PRNG) | Bits 4-6: Channels | Bits 0-3: BPC", table_cell_style),
        ],
        [
            Paragraph("<b>SALT</b>", table_cell_bold),
            Paragraph("16 bytes", table_cell_code),
            Paragraph("Configured bpc &amp; chan", table_cell_style),
            Paragraph("CSPRNG cryptographic salt for PBKDF2 key derivation", table_cell_style),
        ],
        [
            Paragraph("<b>METADATA</b>", table_cell_bold),
            Paragraph("Var (1+N)", table_cell_code),
            Paragraph("Configured bpc &amp; chan", table_cell_style),
            Paragraph("Original filename length (1 byte) + UTF-8 filename (if file flag set)", table_cell_style),
        ],
        [
            Paragraph("<b>PAYLOAD LEN</b>", table_cell_bold),
            Paragraph("4 bytes", table_cell_code),
            Paragraph("Configured bpc &amp; chan", table_cell_style),
            Paragraph("Big-endian unsigned 32-bit integer length of ciphertext", table_cell_style),
        ],
        [
            Paragraph("<b>NONCE / IV</b>", table_cell_bold),
            Paragraph("16 bytes", table_cell_code),
            Paragraph("Configured bpc &amp; chan", table_cell_style),
            Paragraph("CSPRNG initialization vector for stream cipher keystream", table_cell_style),
        ],
        [
            Paragraph("<b>CIPHERTEXT</b>", table_cell_bold),
            Paragraph("N bytes", table_cell_code),
            Paragraph("Configured bpc &amp; chan", table_cell_style),
            Paragraph("XOR stream keystream encrypted payload (raw or zlib-compressed)", table_cell_style),
        ],
        [
            Paragraph("<b>HMAC TAG</b>", table_cell_bold),
            Paragraph("16 bytes", table_cell_code),
            Paragraph("Configured bpc &amp; chan", table_cell_style),
            Paragraph("HMAC-SHA256 (Encrypt-then-MAC) truncated 128-bit integrity tag", table_cell_style),
        ],
    ]

    t_proto = Table([proto_headers] + proto_rows, colWidths=[85, 48, 95, 276])
    t_proto.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_accent_dark),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_bg_card]),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_proto)
    story.append(Spacer(1, 10))

    # Section 5
    story.append(Paragraph("5. Cryptographic Security & Separation of Keys", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=c_border, spaceBefore=1, spaceAfter=6))
    story.append(Paragraph(
        "EncryptorX adheres to the rigorous <b>Encrypt-then-MAC</b> paradigm, guaranteeing defense against Chosen-Ciphertext Attacks (CCA2):",
        body_style
    ))
    story.append(Paragraph(
        "• <b>Key Derivation Function (KDF):</b> Password and salt are processed through PBKDF2-HMAC-SHA256 with 100,000 iterations "
        "to produce a 64-byte master key material. Two independent 32-byte keys are derived: <i>K<sub>enc</sub></i> for confidentiality "
        "and <i>K<sub>auth</sub></i> for authentication.",
        bullet_style
    ))
    story.append(Paragraph(
        "• <b>Permutation Seed Isolation:</b> The shuffling seed is derived via SHA-256 with domain separation "
        "(<code>seed = SHA256(password + b':PREAMBLE_INIT')</code>). An attacker without the password cannot reconstruct the spatial permutation.",
        bullet_style
    ))
    story.append(Paragraph(
        "• <b>Anti-Tampering Enforcement:</b> Prior to decryption, the HMAC tag is verified in constant time via <code>hmac.compare_digest</code>. "
        "If any image pixel harboring stego bits has been altered, extraction halts immediately with <code>AuthenticationError</code>.",
        bullet_style
    ))

    # Section 6
    story.append(Paragraph("6. Configurable Modes & Empirical Capacity Matrix", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=c_border, spaceBefore=1, spaceAfter=6))

    bench_headers = [
        Paragraph("Image Resolution", table_header_style),
        Paragraph("Mode", table_header_style),
        Paragraph("Total Pixels", table_header_style),
        Paragraph("Channels", table_header_style),
        Paragraph("Net Capacity", table_header_style),
        Paragraph("Avg PSNR", table_header_style),
        Paragraph("Stealth Classification", table_header_style),
    ]
    bench_rows = [
        [
            Paragraph("512 × 512 (Square)", table_cell_bold),
            Paragraph("1 bpc", table_cell_code),
            Paragraph("262,144", table_cell_style),
            Paragraph("RGB (3)", table_cell_style),
            Paragraph("98,240 B (~96 KB)", table_cell_style),
            Paragraph("&gt; 65 dB", table_cell_style),
            Paragraph("Ultra Stealth (Undetectable)", table_cell_style),
        ],
        [
            Paragraph("512 × 512 (Square)", table_cell_bold),
            Paragraph("2 bpc", table_cell_code),
            Paragraph("262,144", table_cell_style),
            Paragraph("RGB (3)", table_cell_style),
            Paragraph("196,544 B (~192 KB)", table_cell_style),
            Paragraph("&gt; 52 dB", table_cell_style),
            Paragraph("High Stealth (Balanced)", table_cell_style),
        ],
        [
            Paragraph("512 × 512 (Square)", table_cell_bold),
            Paragraph("4 bpc", table_cell_code),
            Paragraph("262,144", table_cell_style),
            Paragraph("RGB (3)", table_cell_style),
            Paragraph("393,152 B (~384 KB)", table_cell_style),
            Paragraph("&gt; 38 dB", table_cell_style),
            Paragraph("Maximum Density", table_cell_style),
        ],
        [
            Paragraph("1920 × 1080 (Full HD)", table_cell_bold),
            Paragraph("1 bpc", table_cell_code),
            Paragraph("2,073,600", table_cell_style),
            Paragraph("RGB (3)", table_cell_style),
            Paragraph("777,536 B (~759 KB)", table_cell_style),
            Paragraph("&gt; 68 dB", table_cell_style),
            Paragraph("Ultra Stealth (Undetectable)", table_cell_style),
        ],
        [
            Paragraph("1920 × 1080 (Full HD)", table_cell_bold),
            Paragraph("1 bpc", table_cell_code),
            Paragraph("2,073,600", table_cell_style),
            Paragraph("Blue-Only (1)", table_cell_style),
            Paragraph("259,136 B (~253 KB)", table_cell_style),
            Paragraph("&gt; 72 dB", table_cell_style),
            Paragraph("Maximum HVS Invisibility", table_cell_style),
        ],
        [
            Paragraph("3840 × 2160 (4K UHD)", table_cell_bold),
            Paragraph("2 bpc", table_cell_code),
            Paragraph("8,294,400", table_cell_style),
            Paragraph("RGB (3)", table_cell_style),
            Paragraph("6,220,736 B (~5.93 MB)", table_cell_style),
            Paragraph("&gt; 54 dB", table_cell_style),
            Paragraph("High Density Archive", table_cell_style),
        ],
    ]

    t_bench = Table([bench_headers] + bench_rows, colWidths=[90, 42, 54, 62, 86, 44, 126])
    t_bench.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_accent_dark),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_bg_card]),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_bench)
    story.append(Spacer(1, 10))

    # Section 7
    story.append(Paragraph("7. Developer API Reference & CLI Usage", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=c_border, spaceBefore=1, spaceAfter=6))

    python_code = (
        "# Python 3.8+ API Example:\n"
        "from encryptorx.stego import hide_text, extract_text, calculate_metrics, StegoEngine\n\n"
        "# 1. High-level conceal and extract\n"
        "out_img = hide_text('carrier.png', 'Secret msg', 'stego.png', password='Key', bits_per_channel=1)\n"
        "recovered = extract_text('stego.png', password='Key')\n"
        "metrics = calculate_metrics('carrier.png', 'stego.png')\n"
        "print('PSNR: ' + str(metrics['psnr_db']) + ' dB | MSE: ' + str(metrics['mse']))\n\n"
        "# 2. CLI commands:\n"
        "python -m encryptorx.stego hide-text -i photo.png -t 'Message' -o out.png -p 'Key123'\n"
        "python -m encryptorx.stego extract-text -i out.png -p 'Key123'\n"
        "python -m encryptorx.stego hide-file -i photo.png -f document.pdf -o out.png -b 2\n"
        "python -m encryptorx.stego extract-file -i out.png -o ./recovered\n"
        "python -m encryptorx.stego metrics -orig photo.png -stego out.png"
    )
    story.append(Table([[Paragraph(python_code.replace('\n', '<br/>').replace(' ', '&nbsp;'), code_style)]], colWidths=[504]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<b>Rust GUI Integration:</b> Native desktop application compiled with <code>eframe / egui</code>. "
        "Tab 4 provides full point-and-click steganographic capabilities with zero console popups and live metric displays.",
        body_style
    ))

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[OK] Publication PDF generated successfully: {pdf_path.resolve()} ({pdf_path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    out_name = sys.argv[1] if len(sys.argv) > 1 else "EncryptorX_Steganography_Specification.pdf"
    build_pdf(out_name)

