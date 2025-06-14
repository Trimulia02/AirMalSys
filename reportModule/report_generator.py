#!/usr/bin/env python3
import os
import json
import time
import subprocess
import logging
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, LongTable, TableStyle, PageBreak
)
from reportlab.lib.enums import TA_LEFT

# Konfigurasi path
ANALYSIS_DIR = "/home/cuckoo/.cuckoocwd/storage/analyses"
REPORT_DIR = "/home/cuckoo/TA_AnalisisMalware/Report"
PROCESSED_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/processed_reports.json"
INFERENCE_SCRIPT = "/home/cuckoo/TA_AnalisisMalware/resultML/malware_detector.py"
PYTHON_ML_INTERPRETER = "/home/cuckoo/TA_AnalisisMalware/resultML/ml_venv/bin/python3"

START_TIME = time.time()

def load_processed_reports():
    if os.path.exists(PROCESSED_PATH):
        try:
            with open(PROCESSED_PATH, 'r') as f:
                return set(json.load(f))
        except Exception as e:
            logging.warning(f"Failed to load processed reports: {e}")
    return set()

PROCESSED = load_processed_reports()

def find_latest_unprocessed_report_dir():
    candidates = []
    for root, dirs, files in os.walk(ANALYSIS_DIR):
        report_path = os.path.join(root, "task_1", "report.json")
        analysis_path = os.path.join(root, "analysis.json")
        if os.path.exists(report_path) and os.path.exists(analysis_path):
            mtime = os.path.getmtime(report_path)
            if report_path not in PROCESSED and mtime > START_TIME:
                candidates.append((mtime, report_path, analysis_path))
    if candidates:
        candidates.sort(reverse=True)
        return candidates[0][1], candidates[0][2]
    return None

def generate_pdf_report(report_data, analysis_data, ml_binary, ml_family):
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

    # General Info Table
    task = analysis_data.get("tasks", [{}])[0]
    filename = task.get("target", {}).get("filename") or report_data.get("target", {}).get("file", "-")
    general_data = [
        [Paragraph("<b>Task ID</b>", table_cell), Paragraph(str(task.get("id", "-")), table_cell)],
        [Paragraph("<b>Cuckoo Score</b>", table_cell), Paragraph(str(task.get("score", "-")), table_cell)],
        [Paragraph("<b>File Name</b>", table_cell), Paragraph(str(filename), table_cell)]
    ]
    elements.append(Paragraph("General Information", h2))
    general_table = LongTable(general_data, colWidths=[150, 350])
    general_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
    ]))
    elements.append(general_table)
    elements.append(Spacer(1, 12))

    # ML Classification
    ml_data = [
        [Paragraph("<b>Binary Classification</b>", table_cell), Paragraph(f"<font color={'green' if ml_binary=='benign' else 'red'}>{ml_binary.upper()}</font>", table_cell)],
        [Paragraph("<b>Predicted Malware Type</b>", table_cell), Paragraph(str(ml_family), table_cell)]
    ]
    elements.append(Paragraph("Machine Learning Classification", h2))
    ml_table = LongTable(ml_data, colWidths=[150, 350])
    ml_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
    ]))
    elements.append(ml_table)
    elements.append(Spacer(1, 12))

    # Signatures
    sigs = report_data.get("signatures", [])
    if sigs:
        elements.append(Paragraph("Detected Signatures", h2))
        sig_table_data = [[Paragraph("<b>Description</b>", table_cell)]]
        for sig in sigs:
            desc = sig.get("description", "-")
            sig_table_data.append([Paragraph(desc, table_cell)])
        sig_table = LongTable(sig_table_data, colWidths=[500])
        sig_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.black),
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ]))
        elements.append(sig_table)
        elements.append(PageBreak())

    # Processes (optional)
    procs = report_data.get("behavior", {}).get("processes", [])
    if procs:
        elements.append(Paragraph("Processes Observed", h2))
        proc_table_data = [[Paragraph("<b>Process Name</b>", table_cell), Paragraph("<b>PID</b>", table_cell)]]
        for p in procs:
            proc_table_data.append([
                Paragraph(str(p.get("process_name", "-")), table_cell),
                Paragraph(str(p.get("pid", "-")), table_cell)
            ])
        proc_table = LongTable(proc_table_data, colWidths=[350, 150])
        proc_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.black),
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ]))
        elements.append(proc_table)

    doc.build(elements)
    print(f"✅ PDF saved: {pdf_path}")

def main():
    logging.basicConfig(level=logging.INFO)
    print("⏳ Waiting for new analysis...")
    start_time = time.time()

    while True:
        if time.time() - start_time > 3600:
            break
        result = find_latest_unprocessed_report_dir()
        if not result:
            time.sleep(5)
            continue

        report_path, analysis_path = result
        try:
            with open(report_path) as f1, open(analysis_path) as f2:
                report_data = json.load(f1)
                analysis_data = json.load(f2)
        except Exception as e:
            logging.error(f"Failed to load JSON: {e}")
            PROCESSED.add(report_path)
            continue

        try:
            result = subprocess.run([
                PYTHON_ML_INTERPRETER, INFERENCE_SCRIPT, report_path
            ], capture_output=True, text=True, timeout=60)
            ml_out = result.stdout.strip().lower()
            ml_label = "malware" if "malware" in ml_out else "benign" if "benign" in ml_out else "unknown"
            ml_family = "-"
        except Exception as e:
            logging.error(f"ML script failed: {e}")
            ml_label = "unknown"
            ml_family = "-"

        try:
            generate_pdf_report(report_data, analysis_data, ml_label, ml_family)
        except Exception as e:
            logging.error(f"PDF generation failed: {e}")

        PROCESSED.add(report_path)
        with open(PROCESSED_PATH, "w") as f:
            json.dump(list(PROCESSED), f)
        print("🔁 Waiting for next...")

if __name__ == "__main__":
    main()
