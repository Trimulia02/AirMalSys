#!/usr/bin/env python3
import os
import json
import time
import logging
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, LongTable, TableStyle, PageBreak
from reportlab.lib.enums import TA_LEFT

# Konfigurasi path
ANALYSIS_DIR = "/home/cuckoo/.cuckoocwd/storage/analyses"
REPORT_DIR = "/home/cuckoo/TA_AnalisisMalware/Report"
ML_RESULT_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/ml_results.txt"
CVSS_SCORE_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/cvss_score.txt"

def find_latest_analysis():
    latest = None
    latest_mtime = 0
    for root, dirs, files in os.walk(ANALYSIS_DIR):
        if "task_1" in dirs:
            report_path = os.path.join(root, "task_1", "report.json")
            analysis_path = os.path.join(root, "analysis.json")
            if os.path.exists(report_path) and os.path.exists(analysis_path):
                mtime = os.path.getmtime(report_path)
                if mtime > latest_mtime:
                    latest = (report_path, analysis_path)
                    latest_mtime = mtime
    return latest

def read_ml_result():
    try:
        with open(ML_RESULT_PATH, "r") as f:
            for line in f:
                if "malware" in line.lower():
                    return "malware"
                elif "benign" in line.lower():
                    return "benign"
    except:
        pass
    return "benign"

def read_cvss_score():
    try:
        with open(CVSS_SCORE_PATH, "r") as f:
            return f.read().strip()
    except:
        return "-"

def format_timestamp(ts):
    if isinstance(ts, dict) and "__isodt__" in ts:
        try:
            dt = datetime.fromisoformat(ts["__isodt__"].replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return str(ts)
    return str(ts)

def generate_pdf(report_data, analysis_data, ml_label):
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    pdf_path = os.path.join(REPORT_DIR, f"report_{timestamp}.pdf")

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("Heading1", parent=styles["Heading1"], fontSize=16, spaceAfter=14)
    h2 = ParagraphStyle("Heading2", parent=styles["Heading2"], fontSize=13, spaceAfter=8)
    table_cell = ParagraphStyle("TableCell", parent=styles["Normal"], fontSize=10, alignment=TA_LEFT)

    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    elements = []

    elements.append(Paragraph("MALWARE ANALYSIS REPORT", h1))

    # File Info
    target = analysis_data.get("target", {})
    task = analysis_data.get("tasks", [{}])[0]
    score = read_cvss_score()

    file_info = [
        ["Filename", target.get("filename", "-")],
        ["Size (bytes)", str(target.get("size", "-"))],
        ["MD5", target.get("md5", "-")],
        ["SHA1", target.get("sha1", "-")],
        ["SHA256", target.get("sha256", "-")],
        ["Score", score],
        ["Started On", format_timestamp(task.get("started_on", "-"))],
        ["Stopped On", format_timestamp(task.get("stopped_on", "-"))],
    ]
    elements.append(Paragraph("General File Information", h2))
    t = LongTable([[Paragraph(f"<b>{k}</b>", table_cell), Paragraph(v, table_cell)] for k, v in file_info], colWidths=[150, 350])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.black)]))
    elements.append(t)
    elements.append(Spacer(1, 12))

    # Machine Learning Classification
    elements.append(Paragraph("Machine Learning Classification", h2))
    ml_table = LongTable([
        [Paragraph("<b>Classification</b>", table_cell), Paragraph(f"<font color={'red' if ml_label == 'malware' else 'green'}>{ml_label.upper()}</font>", table_cell)],
    ], colWidths=[150, 350])
    ml_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.black)]))
    elements.append(ml_table)
    elements.append(Spacer(1, 12))

    # Signatures
    sigs = report_data.get("signatures", [])
    if sigs:
        elements.append(Paragraph("Detected Signatures", h2))
        sig_table_data = [[Paragraph("<b>No.</b>", table_cell), Paragraph("<b>Description</b>", table_cell)]]
        for idx, sig in enumerate(sigs, 1):
            desc = sig.get("description", "-")
            sig_table_data.append([Paragraph(str(idx), table_cell), Paragraph(desc, table_cell)])
        sig_table = LongTable(sig_table_data, colWidths=[50, 450])
        sig_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ]))
        elements.append(sig_table)
        elements.append(PageBreak())

    # MITRE ATT&CK Techniques
    ttps = analysis_data.get("ttps", [])
    if ttps:
        elements.append(Paragraph("MITRE ATT&CK Techniques", h2))
        mitre_data = [[Paragraph("<b>ID</b>", table_cell), Paragraph("<b>Name</b>", table_cell)]]
        for t in ttps:
            mitre_data.append([Paragraph(t.get("id", "-"), table_cell), Paragraph(t.get("name", "-"), table_cell)])
        mitre_table = LongTable(mitre_data, colWidths=[150, 350])
        mitre_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ]))
        elements.append(mitre_table)
        elements.append(Spacer(1, 12))

    # Proses (bernomor)
    processes = report_data.get("behavior", {}).get("processes", [])
    if processes:
        elements.append(Paragraph("Processes Observed", h2))
        proc_data = [[Paragraph("<b>No.</b>", table_cell), Paragraph("<b>Process Name</b>", table_cell), Paragraph("<b>PID</b>", table_cell)]]
        for i, p in enumerate(processes, 1):
            proc_data.append([
                Paragraph(str(i), table_cell),
                Paragraph(p.get("process_name", "-"), table_cell),
                Paragraph(str(p.get("pid", "-")), table_cell),
            ])
        proc_table = LongTable(proc_data, colWidths=[50, 300, 150])
        proc_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ]))
        elements.append(proc_table)

    doc.build(elements)
    print(f"✅ PDF saved: {pdf_path}")

def main():
    logging.basicConfig(level=logging.INFO)
    result = find_latest_analysis()
    if not result:
        print("❌ Tidak ada laporan ditemukan.")
        return

    report_path, analysis_path = result
    try:
        with open(report_path) as f:
            report_data = json.load(f)
        with open(analysis_path) as f:
            analysis_data = json.load(f)
    except Exception as e:
        print(f"❌ Gagal membaca file JSON: {e}")
        return

    ml_label = read_ml_result()
    generate_pdf(report_data, analysis_data, ml_label)

if __name__ == "__main__":
    main()
