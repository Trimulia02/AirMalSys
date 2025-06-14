#!/usr/bin/env python3
import os
import json
import time
import subprocess
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, LongTable, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib import colors
import logging

# ───── Konfigurasi Path ─────
ANALYSIS_DIR = "/home/cuckoo/.cuckoocwd/storage/analyses"
REPORT_DIR = "/home/cuckoo/TA_AnalisisMalware/Report"
PROCESSED_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/processed_reports.json"

# --- PERUBAHAN KUNCI ADA DI SINI ---
INFERENCE_SCRIPT = "/home/cuckoo/TA_AnalisisMalware/resultML/malware_detector.py"
PYTHON_ML_INTERPRETER = "/home/cuckoo/TA_AnalisisMalware/resultML/ml_venv/bin/python3"
# --- AKHIR PERUBAHAN KUNCI ---

START_TIME = time.time()

def load_processed_reports():
    if os.path.exists(PROCESSED_PATH):
        try:
            with open(PROCESSED_PATH, 'r') as f:
                return set(json.load(f))
        except (json.JSONDecodeError, Exception) as e:
            logging.error(f"Error saat memuat {PROCESSED_PATH}: {e}. Membuat set kosong baru.")
            return set()
    return set()

PROCESSED = load_processed_reports()

def find_latest_unprocessed_report_dir():
    candidates = []
    if not os.path.isdir(ANALYSIS_DIR):
        logging.error(f"Direktori analisis Cuckoo tidak ditemukan: {ANALYSIS_DIR}")
        return None

    for root, dirs, files in os.walk(ANALYSIS_DIR):
        analysis_json_path = os.path.join(root, "analysis.json")
        cuckoo_report_json_path = os.path.join(root, "task_1", "report.json")

        if os.path.exists(analysis_json_path) and os.path.exists(cuckoo_report_json_path):
            try:
                mtime = os.path.getmtime(cuckoo_report_json_path)
                if cuckoo_report_json_path not in PROCESSED and mtime > START_TIME:
                    candidates.append((root, mtime, cuckoo_report_json_path, analysis_json_path))
            except Exception as e:
                logging.error(f"Error saat mengakses mtime untuk {cuckoo_report_json_path}: {e}")
                continue
    
    if not candidates:
        return None
    
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0], candidates[0][2], candidates[0][3]

def generate_pdf_report(cuckoo_report_data, cuckoo_analysis_data, ml_label_binary, ml_probability, ml_label_multiclass):
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    pdf_file_path = os.path.join(REPORT_DIR, f"malware_report_{timestamp}.pdf")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("PdfTitle", parent=styles["Title"], fontSize=18, alignment=TA_LEFT, spaceAfter=16)
    heading_style = ParagraphStyle("PdfHeading", parent=styles["h2"], fontSize=12, alignment=TA_LEFT, spaceBefore=10, spaceAfter=6, fontName='Helvetica-Bold')
    normal_style = ParagraphStyle("PdfNormal", parent=styles["Normal"], fontSize=10, alignment=TA_LEFT, leading=14, spaceAfter=4)
    table_header_style = ParagraphStyle("TableHeader", parent=normal_style, fontName='Helvetica-Bold', alignment=TA_CENTER)
    table_cell_style = ParagraphStyle("TableCell", parent=normal_style, fontSize=9)

    doc = SimpleDocTemplate(pdf_file_path, pagesize=A4,
                            leftMargin=50, rightMargin=50,
                            topMargin=50, bottomMargin=50)
    elements = []

    elements.append(Paragraph("LAPORAN ANALISIS MALWARE", title_style))
    
    elements.append(Paragraph("Informasi Umum", heading_style))
    task_info = cuckoo_analysis_data.get("tasks", [{}])[0]
    general_info_data = [
        (Paragraph("<b>Task ID:</b>", normal_style), Paragraph(str(task_info.get('id', 'N/A')), normal_style)),
        (Paragraph("<b>Skor Cuckoo:</b>", normal_style), Paragraph(str(task_info.get('score', 'N/A')), normal_style)),
    ]
    info_table = LongTable(general_info_data, colWidths=[120, None])
    info_table.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'TOP'), ('LEFTPADDING', (0,0), (-1,-1), 0)]))
    elements.append(info_table)
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Hasil Klasifikasi Machine Learning", heading_style))
    ml_color = "green" if ml_label_binary.lower() == "benign" else "red"
    ml_result_data = [
        (Paragraph("<b>Klasifikasi Biner:</b>", normal_style), Paragraph(f"<font color='{ml_color}'>{ml_label_binary.upper()}</font>", normal_style)),
        (Paragraph("<b>Prediksi Jenis Malware:</b>", normal_style), Paragraph(str(ml_label_multiclass), normal_style)),
    ]
    ml_table = LongTable(ml_result_data, colWidths=[150, None])
    ml_table.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'TOP'), ('LEFTPADDING', (0,0), (-1,-1), 0)]))
    elements.append(ml_table)
    elements.append(Spacer(1, 12))

    doc.build(elements)
    print(f"✅ Laporan PDF berhasil dibuat: {pdf_file_path}")

def main():
    print("♻️  Menunggu laporan baru...")
    MAX_RUNTIME = 3600
    script_start_time = time.time()

    while True:
        if time.time() - script_start_time > MAX_RUNTIME:
            logging.info("Waktu maksimum tercapai. Menghentikan proses.")
            break
        
        latest_report_info = find_latest_unprocessed_report_dir()
        
        if not latest_report_info:
            time.sleep(5)
            continue

        analysis_root_dir, cuckoo_report_json_path, analysis_json_path = latest_report_info
        
        try:
            with open(cuckoo_report_json_path, 'r') as f: cuckoo_report_data = json.load(f)
            with open(analysis_json_path, 'r') as f: cuckoo_analysis_data = json.load(f)
        except Exception as e:
            logging.error(f"Error saat memuat data laporan untuk {cuckoo_report_json_path}: {e}")
            PROCESSED.add(cuckoo_report_json_path)
            with open(PROCESSED_PATH, "w") as f: json.dump(list(PROCESSED), f)
            continue
            
        ml_command = [
            PYTHON_ML_INTERPRETER,
            INFERENCE_SCRIPT,
            cuckoo_report_json_path,
        ]
        
        print("🚀 Menjalankan inference ML...")
        ml_label_binary = "unknown"
        
        try:
            result = subprocess.run(ml_command, check=True, capture_output=True, text=True, timeout=60)
            output_line = result.stdout.strip().lower()
            if "malware" in output_line:
                ml_label_binary = "malware"
            elif "benign" in output_line:
                ml_label_binary = "benign"
            else:
                logging.warning(f"Output tidak dikenali dari skrip ML: {result.stdout.strip()}")

            # ✅ Tambahkan hasil klasifikasi ke terminal
            print(f"🧠 Hasil klasifikasi ML: {ml_label_binary.upper()}")

        except subprocess.CalledProcessError as e:
            logging.error(f"Error saat menjalankan skrip inference ML: {e}\nStderr: {e.stderr}")
        except Exception as e:
            logging.error(f"Terjadi error tak terduga saat menjalankan ML: {e}")

        ml_probability = 0.0
        ml_label_multiclass = "-"

        try:
            generate_pdf_report(cuckoo_report_data, cuckoo_analysis_data, ml_label_binary, ml_probability, ml_label_multiclass)
        except Exception as e:
            logging.error(f"Gagal membuat laporan PDF untuk {cuckoo_report_json_path}: {e}", exc_info=True)
            
        PROCESSED.add(cuckoo_report_json_path)
        try:
            with open(PROCESSED_PATH, "w") as f:
                json.dump(list(PROCESSED), f)
        except Exception as e:
            logging.error(f"Gagal menyimpan daftar laporan yang sudah diproses: {e}")

        print(f"🕒 Menunggu laporan berikutnya... ({len(PROCESSED)} laporan total dalam log)\n")
        time.sleep(5)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    main()
