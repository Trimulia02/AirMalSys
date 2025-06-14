# /home/cuckoo/TA_AnalisisMalware/Cuckoo Upload/ui/report_summary.py

from PyQt5.QtWidgets import QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QGridLayout
from PyQt5.QtGui import QFont, QPainter, QPen
from PyQt5.QtCore import Qt
import os
import glob
from datetime import datetime
import logging
import json

ANALYSIS_DIR_CUCKOO = "/home/cuckoo/.cuckoocwd/storage/analyses"
CUSTOM_PDF_REPORT_DIR = "/home/cuckoo/TA_AnalisisMalware/Report"
ML_RESULT_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/ml_results.txt"


class GaugeWidget(QWidget):
    def __init__(self, score=0, parent=None):
        super().__init__(parent)
        self.score = 0.0
        self.set_score(score)
        self.setMinimumSize(150, 150)

    def set_score(self, score):
        print(f"DEBUG GAUGE SET_SCORE: Menerima skor: {score}, Tipe: {type(score)}")
        try:
            self.score = float(score)
        except (ValueError, TypeError):
            logging.warning(f"GaugeWidget: Skor tidak valid '{score}', diatur ke 0.0.")
            self.score = 0.0
        print(f"DEBUG GAUGE SET_SCORE: self.score diatur ke: {self.score}")
        self.update()

    def paintEvent(self, event):
        painter = QPainter()
        if not painter.begin(self):
            logging.error("GaugeWidget: QPainter.begin() gagal.")
            return
        try:
            painter.setRenderHint(QPainter.Antialiasing)
            rect = self.rect()
            center = rect.center()
            radius_float = min(rect.width(), rect.height()) / 2.0 - 20.0
            if radius_float <= 0:
                if painter.isActive(): painter.end()
                return
            
            x_coord = int(center.x() - radius_float)
            y_coord = int(center.y() - radius_float)
            width = int(2 * radius_float)
            height = int(2 * radius_float)

            if width <= 0 or height <= 0:
                if painter.isActive(): painter.end()
                return
            
            painter.setPen(QPen(Qt.gray, 20))
            painter.drawArc(x_coord, y_coord, width, height, 45 * 16, 270 * 16)
            
            current_score_float = self.score
            clamped_score = max(0.0, min(current_score_float, 10.0))
            angle_span = int((clamped_score / 10.0) * 270.0)
            
            score_arc_color = Qt.darkGray
            if clamped_score >= 8: 
                score_arc_color = Qt.red
            elif clamped_score >= 6: 
                score_arc_color = Qt.GlobalColor.orange
            elif clamped_score >= 3: 
                score_arc_color = Qt.yellow
            else: 
                score_arc_color = Qt.green
            
            painter.setPen(QPen(score_arc_color, 20))
            painter.drawArc(x_coord, y_coord, width, height, (45 + (270 - angle_span)) * 16, angle_span * 16)
            
            # ---- DEBUGGING UNTUK TEKS SKOR ----
            print(f"DEBUG GAUGE PAINT EVENT (setelah Analisa Ulang atau pemanggilan lain):")
            print(f"  self.rect(): width={rect.width()}, height={rect.height()}")
            print(f"  current_score_float (dari self.score): {current_score_float}")
            print(f"  clamped_score: {clamped_score}")
            
            text_to_draw = f"{clamped_score:.1f}\nScore"
            print(f"  Teks yang akan digambar: '{text_to_draw}'")

            painter.setPen(Qt.white) 
            font = QFont("Arial", 16, QFont.Bold) 
            painter.setFont(font)
            print(f"  Font yang digunakan: Family='{font.family()}', PointSize={font.pointSize()}, Bold={font.bold()}")
            
            # Uji coba gambar teks sederhana jika ada masalah
            # painter.fillRect(rect, Qt.magenta) # Untuk melihat area gambar
            # painter.setPen(Qt.black)
            # painter.drawText(rect, Qt.AlignCenter, "TEST SKOR")
            
            painter.drawText(rect, Qt.AlignCenter, text_to_draw) # Baris yang menggambar skor
            # ---- AKHIR DEBUGGING ----

        except Exception as e:
            logging.error(f"GaugeWidget: Terjadi error saat paintEvent: {e}", exc_info=True)
        finally:
            if painter.isActive():
                painter.end()

class ResultSummaryWidget(QWidget):
    def __init__(self, on_restart_analysis, parent=None):
        super().__init__(parent)
        self.on_restart_analysis = on_restart_analysis
        self.setStyleSheet("background-color: #2b2b2b; color: white;")
        self.pdf_path = None
        self.initUI()

    def initUI(self):
        main_layout = QVBoxLayout()
        content_layout = QHBoxLayout()
        button_layout = QHBoxLayout()
        left_frame = QVBoxLayout()
        self.gauge = GaugeWidget()
        self.categoryLabel = QLabel("Kategori : -")
        self.categoryLabel.setAlignment(Qt.AlignCenter)
        self.categoryLabel.setStyleSheet("background-color: gray; padding: 8px; border-radius: 8px; font-weight: bold;")
        left_frame.addWidget(QLabel("Skor Perilaku", alignment=Qt.AlignCenter))
        left_frame.addWidget(self.gauge, alignment=Qt.AlignCenter)
        left_frame.addWidget(self.categoryLabel)
        right_frame = QGridLayout()
        title = QLabel("Keterangan Malware")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        right_frame.addWidget(title, 0, 0, 1, 2)
        self.fields = {
            "Jenis": QLabel("-"), "Nama": QLabel("-"), "Ukuran": QLabel("-"),
            "Task ID": QLabel("-"), "Kategori": QLabel("-"),
            "Waktu Analisis": QLabel("-"), "Lingkungan": QLabel("-")
        }
        for i, (key, label) in enumerate(self.fields.items()):
            key_lbl = QLabel(key)
            key_lbl.setStyleSheet("font-weight: bold;")
            right_frame.addWidget(key_lbl, i + 1, 0)
            right_frame.addWidget(label, i + 1, 1)
        content_layout.addLayout(left_frame, 1)
        content_layout.addLayout(right_frame, 2)
        self.viewPdfButton = QPushButton("Lihat PDF")
        self.viewPdfButton.setStyleSheet("background-color: #00e676; color: black; padding: 10px; font-weight: bold; border-radius: 8px;")
        self.viewPdfButton.clicked.connect(self.open_pdf)
        self.restartButton = QPushButton("Analisa Ulang")
        self.restartButton.setStyleSheet("background-color: #2979ff; color: white; padding: 10px; font-weight: bold; border-radius: 8px;")
        self.restartButton.clicked.connect(self.on_restart_analysis)
        button_layout.addWidget(self.viewPdfButton)
        button_layout.addWidget(self.restartButton)
        main_layout.addLayout(content_layout)
        main_layout.addSpacing(20)
        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

    def _find_latest_cuckoo_analysis_paths(self):
        if not os.path.isdir(ANALYSIS_DIR_CUCKOO):
            logging.error(f"ResultSummary: Direktori Cuckoo ({ANALYSIS_DIR_CUCKOO}) tidak ditemukan.")
            print(f"DEBUG: Direktori Cuckoo ({ANALYSIS_DIR_CUCKOO}) tidak ditemukan.")
            return None, None
        candidates = []
        print(f"DEBUG: Mencari di ANALYSIS_DIR_CUCKOO: {ANALYSIS_DIR_CUCKOO}")
        for root, dirs, files in os.walk(ANALYSIS_DIR_CUCKOO):
            analysis_json_path = os.path.join(root, "analysis.json")
            cuckoo_report_json_path = os.path.join(root, "task_1", "report.json")
            if os.path.exists(analysis_json_path) and os.path.exists(cuckoo_report_json_path):
                try:
                    mtime = os.path.getmtime(cuckoo_report_json_path) 
                    candidates.append((mtime, analysis_json_path, cuckoo_report_json_path))
                except Exception as e:
                    logging.warning(f"ResultSummary: Gagal mendapatkan mtime untuk file di {root}: {e}")
        if not candidates:
            logging.info("ResultSummary: Tidak ada kandidat file analisis Cuckoo yang valid ditemukan (setelah os.walk).")
            print("DEBUG: Tidak ada kandidat file analisis Cuckoo yang valid ditemukan (setelah os.walk).")
            return None, None
        candidates.sort(key=lambda x: x[0], reverse=True)
        logging.info(f"ResultSummary: File analisis Cuckoo terbaru dipilih: {candidates[0][1]}")
        print(f"DEBUG: File analisis Cuckoo terbaru dipilih: analysis.json='{candidates[0][1]}', report.json='{candidates[0][2]}'")
        return candidates[0][1], candidates[0][2]

    def _read_ml_results(self):
        predicted_family = "-"
        # --- AWAL BLOK KODE UNTUK MEMBACA ML_RESULTS.TXT (DIKOMENTARI) ---
        """
        if os.path.exists(ML_RESULT_PATH):
            try:
                with open(ML_RESULT_PATH, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("Predicted family:"):
                            family = line.split(":", 1)[1].strip()
                            if family: 
                                predicted_family = family
                            break 
                logging.info(f"ResultSummary: Predicted family dari {ML_RESULT_PATH}: {predicted_family}")
            except Exception as e:
                logging.error(f"ResultSummary: Gagal membaca atau parse {ML_RESULT_PATH}: {e}")
        else:
            logging.warning(f"ResultSummary: File {ML_RESULT_PATH} tidak ditemukan.")
        """
        # --- AKHIR BLOK KODE UNTUK MEMBACA ML_RESULTS.TXT ---
        return predicted_family

    def load_latest_report(self):
        logging.info("ResultSummary: Memulai load_latest_report...")
        print("DEBUG: Memulai load_latest_report...")

        latest_custom_pdf_path = None
        analysis_time_str = "-"
        generated_pdfs = glob.glob(os.path.join(CUSTOM_PDF_REPORT_DIR, "malware_report_*.pdf"))
        if generated_pdfs:
            latest_custom_pdf_path = max(generated_pdfs, key=os.path.getmtime)
            self.pdf_path = latest_custom_pdf_path
            try:
                analysis_time_ts = os.path.getmtime(latest_custom_pdf_path)
                analysis_time_str = datetime.fromtimestamp(analysis_time_ts).strftime('%Y-%m-%d %H:%M:%S')
            except Exception as e:
                logging.error(f"ResultSummary: Gagal mendapatkan mtime PDF kustom '{latest_custom_pdf_path}': {e}")
        else:
            logging.warning("ResultSummary: Tidak ada PDF kustom ditemukan di CUSTOM_PDF_REPORT_DIR.")

        cuckoo_analysis_json_path, _ = self._find_latest_cuckoo_analysis_paths()
        analysis_data = {}
        if cuckoo_analysis_json_path:
            try:
                with open(cuckoo_analysis_json_path, 'r') as f:
                    analysis_data = json.load(f)
                logging.info(f"ResultSummary: Berhasil memuat analysis.json: {cuckoo_analysis_json_path}")
                print(f"DEBUG: analysis.json dimuat: {cuckoo_analysis_json_path}")
            except Exception as e:
                logging.error(f"ResultSummary: Gagal memuat atau parse {cuckoo_analysis_json_path}: {e}", exc_info=True)
                print(f"DEBUG: GAGAL memuat {cuckoo_analysis_json_path}: {e}")
                analysis_data = {}
        else:
            logging.warning("ResultSummary: Path analysis.json Cuckoo tidak ditemukan.")
            print("DEBUG: Path analysis.json Cuckoo tidak ditemukan.")

        task_id_val = "N/A"
        file_name_val = "N/A"
        predicted_family_val = self._read_ml_results()
        file_type_from_cuckoo_info = "-" 
        file_size_str = "-"
        lingkungan_val = "Windows (Sandbox)"
        score_value = 0.0
        category_value = "Tidak Ada Laporan"

        if analysis_data: # Hanya proses jika analysis_data berhasil dimuat
            task_id_val = analysis_data.get("id", "N/A")
            target_info = analysis_data.get("target", {})
            file_name_val = target_info.get("filename", "N/A")
            file_type_from_cuckoo_info = target_info.get("filetype", "-")
            file_size_bytes = target_info.get("size", 0)
            if isinstance(file_size_bytes, (int, float)) and file_size_bytes > 0:
                file_size_str = f"{file_size_bytes / 1024:.2f} KB" if file_size_bytes >= 1024 else f"{file_size_bytes} bytes"
            elif file_size_bytes == 0 and file_name_val != "N/A":
                file_size_str = "0 bytes"
            
            lingkungan_val = analysis_data.get("tasks", [{}])[0].get("platform", "Windows") + " (Sandbox)" \
                             if analysis_data.get("tasks") else "Windows (Sandbox)"

            cuckoo_score_from_json = analysis_data.get("score")
            if not cuckoo_score_from_json and analysis_data.get("tasks"): # Fallback ke skor task pertama
                first_task_info = analysis_data.get("tasks")[0]
                cuckoo_score_from_json = first_task_info.get("score")

            if cuckoo_score_from_json is not None:
                try:
                    score_value = float(cuckoo_score_from_json)
                    # Logika penentuan kategori berdasarkan skor
                    if score_value >= 8: 
                        category_value = "Sangat Berbahaya"
                    elif score_value >= 6: 
                        category_value = "Berbahaya"
                    elif score_value >= 3: 
                        category_value = "Mencurigakan"
                    elif score_value >= 0: 
                        category_value = "Tidak Berbahaya"
                    else: # Skor negatif
                        category_value = "Skor Tidak Valid"
                except ValueError:
                    logging.warning(f"Skor Cuckoo '{cuckoo_score_from_json}' tidak valid. Menggunakan skor default 0.0.")
                    score_value = 0.0 # Jika parse gagal, skor jadi 0
                    category_value = "Data Skor Tidak Valid"
            else: # Tidak ada field 'score' di analysis.json
                 score_value = 0.0
                 category_value = "Skor Tidak Tersedia"
        
        else: # analysis_data kosong (tidak ada JSON Cuckoo yang dimuat atau gagal parse)
            if not latest_custom_pdf_path: # Tidak ada PDF kustom juga
                category_value = "Tidak Ada Laporan"
                score_value = 0.0 # Pastikan skor direset
                # Semua field lain sudah default N/A atau -
            else: # Ada PDF, tapi tidak ada data JSON Cuckoo.
                category_value = "Data Analisis Tidak Ditemukan"
                score_value = 0.0 # Skor tetap 0 jika data analisis tidak ada
                if file_name_val == "N/A" and latest_custom_pdf_path: # Default file_name_val dari inisialisasi
                     file_name_val = os.path.basename(latest_custom_pdf_path) # Ambil nama dari PDF
        
        jenis_display_val = predicted_family_val
        # if jenis_display_val == "-": # Opsi fallback jika ML "-"
        #     jenis_display_val = file_type_from_cuckoo_info


        metadata = {
            "Jenis": jenis_display_val,
            "Nama": file_name_val,
            "Ukuran": file_size_str,
            "Task ID": task_id_val,
            "Kategori": category_value,
            "Waktu Analisis": analysis_time_str,
            "Lingkungan": lingkungan_val
        }
        
        print(f"DEBUG UI LOAD: Skor FINAL yang akan dikirim: {score_value}, Tipe: {type(score_value)}")
        print(f"DEBUG UI LOAD: Kategori FINAL: {category_value}")
        print(f"DEBUG UI LOAD: Data akhir untuk UI Metadata: {metadata}")
        self.update_summary(score_value, category_value, metadata, latest_custom_pdf_path)

    def update_summary(self, score, category, metadata, pdf_path):
        print(f"DEBUG UI UPDATE: Menerima skor: {score}, Tipe: {type(score)}")
        self.gauge.set_score(score)
        self.categoryLabel.setText(f"Kategori : {category}")
        self.pdf_path = pdf_path
        category_lower = category.lower()
        
        if "sangat berbahaya" in category_lower:
            self.categoryLabel.setStyleSheet("background-color: #c00000; color: white; padding: 8px; border-radius: 8px; font-weight: bold;")
        elif "berbahaya" in category_lower:
            self.categoryLabel.setStyleSheet("background-color: #ff8c00; color: white; padding: 8px; border-radius: 8px; font-weight: bold;")
        elif "mencurigakan" in category_lower:
            self.categoryLabel.setStyleSheet("background-color: #ffc107; color: black; padding: 8px; border-radius: 8px; font-weight: bold;")
        elif "tidak berbahaya" in category_lower:
             self.categoryLabel.setStyleSheet("background-color: #28a745; color: white; padding: 8px; border-radius: 8px; font-weight: bold;")
        elif "tidak ada laporan" in category_lower or \
             "skor tidak tersedia" in category_lower or \
             "data skor tidak valid" in category_lower or \
             "skor tidak valid" in category_lower or \
             "data analisis tidak ditemukan" in category_lower:
             self.categoryLabel.setStyleSheet("background-color: #6c757d; color: white; padding: 8px; border-radius: 8px; font-weight: bold;")
        else:
            self.categoryLabel.setStyleSheet("background-color: gray; color: white; padding: 8px; border-radius: 8px; font-weight: bold;")
        
        for key, label_widget in self.fields.items():
            label_widget.setText(str(metadata.get(key, "-")))
        if "Kategori" in self.fields:
             self.fields["Kategori"].setText(category)

    def open_pdf(self):
        if hasattr(self, 'pdf_path') and self.pdf_path and os.path.exists(self.pdf_path):
            logging.info(f"ReportSummary: Membuka PDF: {self.pdf_path}")
            if os.name == 'posix':
                 if 'darwin' in os.uname().sysname.lower(): os.system(f'open "{self.pdf_path}"')
                 else: os.system(f'xdg-open "{self.pdf_path}"')
            elif os.name == 'nt':
                try: os.startfile(self.pdf_path)
                except Exception as e: logging.error(f"ReportSummary: Gagal membuka PDF di Windows: {e}")
            else: logging.warning(f"ReportSummary: OS tidak didukung untuk membuka PDF: {os.name}")
        else:
            logging.warning(f"ReportSummary: Path PDF tidak diatur atau file tidak ada: {getattr(self, 'pdf_path', 'N/A')}")