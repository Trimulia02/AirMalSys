#!/usr/bin/env python3
import os
import json
import logging
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, LongTable, TableStyle, PageBreak, Frame, PageTemplate
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib.units import cm

# --- KONFIGURASI ---
# Sesuaikan path ini dengan lingkungan Anda
ANALYSIS_DIR = "/home/cuckoo/.cuckoocwd/storage/analyses"
REPORT_DIR = "/home/cuckoo/TA_AnalisisMalware/Report"
ML_RESULT_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/ml_results.txt"
CVSS_SCORE_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/cvss_score.txt"

# --- PALET WARNA & GAYA ---
# Palet warna yang lebih modern untuk tampilan profesional
COLOR_PRIMARY_DARK = colors.HexColor("#2C3E50")  # Biru Gelap Keabuan
COLOR_PRIMARY = colors.HexColor("#3498DB")      # Biru Cerah
COLOR_ACCENT = colors.HexColor("#E74C3C")       # Merah
COLOR_LIGHT_GREY = colors.HexColor("#ECF0F1")   # Abu-abu Sangat Terang
COLOR_MEDIUM_GREY = colors.HexColor("#BDC3C7")  # Abu-abu
COLOR_TEXT = colors.HexColor("#34495E")         # Warna Teks Utama

# --- FUNGSI HELPER (Tidak Berubah Banyak) ---

def find_latest_analysis():
    """Menemukan report.json dan analysis.json terbaru berdasarkan mtime."""
    latest_report = None
    latest_analysis = None
    latest_time = 0

    for root, _, files in os.walk(ANALYSIS_DIR):
        if "report.json" in files:
            report_path = os.path.join(root, "report.json")
            mtime = os.path.getmtime(report_path)

            if mtime > latest_time:
                # Coba cari analysis.json satu atau dua level di atas
                candidate_analysis_1 = os.path.abspath(os.path.join(report_path, "../../analysis.json"))
                candidate_analysis_2 = os.path.abspath(os.path.join(report_path, "../../../analysis.json"))

                if os.path.exists(candidate_analysis_1):
                    latest_analysis = candidate_analysis_1
                    latest_report = report_path
                    latest_time = mtime
                elif os.path.exists(candidate_analysis_2):
                    latest_analysis = candidate_analysis_2
                    latest_report = report_path
                    latest_time = mtime

    if latest_report and latest_analysis:
        return latest_report, latest_analysis

    logging.warning("Tidak dapat menemukan laporan analisis yang valid.")
    return None

def read_ml_results():
    """Membaca hasil klasifikasi dari file teks."""
    if not os.path.exists(ML_RESULT_PATH):
        return "Tidak Diketahui", "Tidak Diketahui", "-"
    try:
        with open(ML_RESULT_PATH, "r") as f:
            lines = [line.strip() for line in f.readlines()]
            if len(lines) >= 3:
                jenis = "Malware" if "malware" in lines[0].lower() else "Benign"
                confidence = f"{float(lines[1]) * 100:.1f}%"
                family = lines[2] if lines[2] else "-"
                return jenis, family, confidence
            elif len(lines) >= 2:
                jenis = "Malware" if "malware" in lines[0].lower() else "Benign"
                confidence = f"{float(lines[1]) * 100:.1f}%"
                return jenis, "-", confidence
    except Exception as e:
        logging.error(f"Error membaca hasil ML: {e}")
    return "Tidak Diketahui", "Tidak Diketahui", "-"

def read_cvss_score():
    """Membaca skor CVSS dari file teks."""
    try:
        with open(CVSS_SCORE_PATH, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "-"
    except Exception as e:
        logging.error(f"Error membaca skor CVSS: {e}")
        return "-"

def get_cvss_severity(score_str):
    """Mengonversi skor CVSS numerik menjadi tingkat keparahan (severity)."""
    try:
        score = float(score_str)
        if score == 0:
            return "None"
        elif 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        elif 9.0 <= score <= 10.0:
            return "Critical"
        else:
            return "Unknown"
    except (ValueError, TypeError):
        return "N/A"
from datetime import datetime, timezone, timedelta

def format_timestamp(ts):
    """Memformat timestamp ISO 8601 dari Cuckoo menjadi waktu lokal (WIB)."""
    try:
        # Ubah string ISO ke objek datetime dengan timezone UTC
        dt_utc = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        # Konversi ke zona waktu WIB (UTC+7)
        dt_wib = dt_utc.astimezone(timezone(timedelta(hours=7)))
        return dt_wib.strftime("%Y-%m-%d %H:%M:%S WIB")
    except (AttributeError, ValueError):
        return str(ts)

# --- FUNGSI PEMBUATAN PDF (REWORKED) ---
class ReportPDFTemplate(PageTemplate):
    """Template untuk mengatur header dan footer pada setiap halaman."""
    def __init__(self, id, doc):
        self.doc = doc
        frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='normal')
        super().__init__(id, [frame])

    def beforeDrawPage(self, canvas, doc):
        """Dipanggil sebelum halaman digambar."""
        # Header
        canvas.saveState()
        canvas.setFillColor(COLOR_PRIMARY_DARK)
        canvas.setFont('Helvetica-Bold', 12)
        canvas.drawString(doc.leftMargin, A4[1] - 1.5 * cm, "Malware Analysis Report")
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(COLOR_TEXT)
        canvas.drawRightString(A4[0] - doc.rightMargin, A4[1] - 1.5 * cm, f"Created on: {datetime.now().strftime('%Y-%m-%d')}")
        canvas.setStrokeColor(COLOR_LIGHT_GREY)
        canvas.line(doc.leftMargin, A4[1] - 1.8 * cm, A4[0] - doc.rightMargin, A4[1] - 1.8 * cm)
        canvas.restoreState()

        # Footer
        canvas.saveState()
        canvas.setStrokeColor(COLOR_LIGHT_GREY)
        canvas.line(doc.leftMargin, doc.bottomMargin - 0.2 * cm, A4[0] - doc.rightMargin, doc.bottomMargin - 0.2 * cm)
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(COLOR_MEDIUM_GREY)
        canvas.drawCentredString(A4[0] / 2, doc.bottomMargin - 0.6 * cm, f"Page {doc.page}")
        canvas.restoreState()

def create_styled_table(data, col_widths):
    """Membuat tabel dengan gaya yang sudah ditentukan."""
    tbl = LongTable(data, colWidths=col_widths)
    style = TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, 0), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BACKGROUND', (0, 0), (-1, 0), COLOR_PRIMARY_DARK),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('TEXTCOLOR', (0, 1), (-1, -1), COLOR_TEXT),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, COLOR_MEDIUM_GREY),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
    ])
    tbl.setStyle(style)
    return tbl

def generate_pdf(report_data, analysis_data, jenis, family, confidence):
    """Fungsi utama untuk menghasilkan file PDF."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    pdf_path = os.path.join(REPORT_DIR, f"report_{timestamp}.pdf")

    # Inisialisasi Dokumen dengan margin
    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2.5*cm, bottomMargin=2.5*cm)

    # Menyiapkan Stylesheet
    styles = getSampleStyleSheet()
    style_h1 = ParagraphStyle("H1", parent=styles["h1"], fontName="Helvetica-Bold", fontSize=18,
                              textColor=COLOR_PRIMARY_DARK, spaceAfter=12, alignment=TA_LEFT)
    style_h2 = ParagraphStyle("H2", parent=styles["h2"], fontName="Helvetica-Bold", fontSize=14,
                              textColor=COLOR_PRIMARY_DARK, spaceAfter=10, spaceBefore=12, alignment=TA_LEFT)
    style_body = ParagraphStyle("Body", parent=styles["Normal"], fontName="Helvetica", fontSize=10,
                                textColor=COLOR_TEXT, alignment=TA_LEFT, leading=14)
    style_table_cell = ParagraphStyle("TableCell", parent=style_body, fontSize=9)
    style_table_header = ParagraphStyle("TableHeader", parent=style_table_cell, fontName="Helvetica-Bold", textColor=colors.white)

    elements = []
    
    # Menambahkan template header/footer
    doc.addPageTemplates([ReportPDFTemplate('main', doc)])

    # --- Bagian Ringkasan ---
    elements.append(Paragraph("Analysis Summary", style_h2))
    
    target = analysis_data.get("target", {})
    submitted = analysis_data.get("submitted", {})
    tasks = analysis_data.get("tasks", [])
    task = tasks[0] if tasks else {}
    analysis_id = analysis_data.get("id", "-")
    score = read_cvss_score()
    severity = get_cvss_severity(score)

    style_table_cell_white = ParagraphStyle("TableCellWhite", parent=style_table_cell, textColor=colors.white)
    summary_data = [
        [Paragraph("<b>Analysis ID</b>", style_table_cell_white), Paragraph(analysis_id, style_table_cell)],
        [Paragraph("<b>File Name</b>", style_table_cell_white), Paragraph(target.get("filename", "-"), style_table_cell)],
        [Paragraph("<b>File Size</b>", style_table_cell_white), Paragraph(str(target.get("size", "-")), style_table_cell)],
        [Paragraph("<b>MD5</b>", style_table_cell_white), Paragraph(submitted.get("md5", "-"), style_table_cell)],
        [Paragraph("<b>SHA256</b>", style_table_cell_white), Paragraph(submitted.get("sha256", "-"), style_table_cell)],
        [Paragraph("<b>Start Time</b>", style_table_cell_white), Paragraph(format_timestamp(task.get("started_on", {}).get("__isodt__", "-")), style_table_cell)],
        [Paragraph("<b>End Time</b>", style_table_cell_white), Paragraph(format_timestamp(task.get("stopped_on", {}).get("__isodt__", "-")), style_table_cell)],
        [Paragraph("<b>Severity Score</b>", style_table_cell_white), Paragraph(f"{score} ({severity})", style_table_cell)],
        [Paragraph("<b>Classification</b>", style_table_cell_white), Paragraph(f"<b>{jenis}</b> (Confidence: {confidence})", style_table_cell)],
        [Paragraph("<b>Malware Family</b>", style_table_cell_white), Paragraph(family, style_table_cell)],
    ]
    
    summary_table = LongTable(summary_data, colWidths=[3.5*cm, None])
    summary_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, COLOR_MEDIUM_GREY),
        ('BACKGROUND', (0, 0), (0, -1), COLOR_PRIMARY_DARK),  # Kolom kiri (label)
        ('TEXTCOLOR', (0, 0), (0, -1), colors.white),         # Teks kolom kiri
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),      # Bold teks kolom kiri
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 1*cm))

    # --- Bagian Signatures ---
    sigs = report_data.get("signatures", [])
    if sigs:
        elements.append(Paragraph("Detected Signatures", style_h2))
        sig_data = [[Paragraph(h, style_table_header) for h in ["No.", "Signature Name", "Description"]]]
        for idx, sig in enumerate(sigs, 1):
            sig_name = sig.get("name", "-")
            desc = sig.get("description", "-")
            sig_data.append([
                Paragraph(str(idx), style_table_cell),
                Paragraph(sig_name, style_table_cell),
                Paragraph(desc, style_table_cell)
            ])

        sig_table = create_styled_table(sig_data, col_widths=[1.5*cm, 5*cm, None])
        elements.append(sig_table)
        elements.append(PageBreak())

    # --- Bagian Proses ---
    processes = report_data.get("behavior", {}).get("processes", [])
    if processes:
        elements.append(Paragraph("Proses yang Dijalankan", style_h2))
        proc_data = [[Paragraph(h, style_table_header) for h in ["No.", "Nama Proses", "PID", "Parent PID"]]]
        for i, p in enumerate(processes, 1):
            proc_data.append([
                Paragraph(str(i), style_table_cell),
                Paragraph(p.get("process_name", "-"), style_table_cell),
                Paragraph(str(p.get("pid", "-")), style_table_cell),
                Paragraph(str(p.get("ppid", "-")), style_table_cell),
            ])
        proc_table = create_styled_table(proc_data, col_widths=[1.5*cm, None, 2*cm, 2*cm])
        elements.append(proc_table)

    # Build PDF
    try:
        doc.build(elements)
        logging.info(f"✅ PDF berhasil disimpan: {pdf_path}")
    except Exception as e:
        logging.error(f"❌ Gagal membuat PDF: {e}")

def main():
    """Fungsi utama untuk menjalankan skrip."""
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    result = find_latest_analysis()
    if not result:
        logging.error("❌ Tidak ada laporan analisis Cuckoo yang ditemukan. Pastikan path ANALYSIS_DIR sudah benar.")
        return

    report_path, analysis_path = result
    logging.info(f"Menggunakan laporan dari: {report_path}")
    
    try:
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        with open(analysis_path, 'r') as f:
            analysis_data = json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"❌ Gagal mem-parsing file JSON: {e}. File mungkin korup atau tidak lengkap.")
        return
    except Exception as e:
        logging.error(f"❌ Gagal membaca file laporan: {e}")
        return

    jenis, family, confidence = read_ml_results()
    generate_pdf(report_data, analysis_data, jenis, family, confidence)

if __name__ == "__main__":
    main()
