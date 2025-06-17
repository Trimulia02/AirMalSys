from PyQt5.QtWidgets import QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QGridLayout, QFrame
from PyQt5.QtGui import QFont, QPainter, QPen, QColor, QBrush, QLinearGradient
from PyQt5.QtCore import Qt, QRectF
import os
import logging
import json
from datetime import datetime

# --- PATH KONSTAN (TIDAK ADA PERUBAHAN) ---
ANALYSIS_DIR_CUCKOO = "/home/cuckoo/.cuckoocwd/storage/analyses"
CUSTOM_PDF_REPORT_DIR = "/home/cuckoo/TA_AnalisisMalware/Report"
ML_RESULT_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/ml_results.txt"


class GaugeWidget(QWidget):
    def __init__(self, score=0, parent=None):
        super().__init__(parent)
        self.score = 0.0
        self.set_score(score)
        self.setMinimumSize(180, 180)

    def set_score(self, score):
        try:
            self.score = float(score)
        except (ValueError, TypeError):
            self.score = 0.0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        rect = self.rect()
        side = min(rect.width(), rect.height())
        
        gauge_rect = QRectF(15, 15, side - 30, side - 30)

        pen = QPen(QColor("#E0E0E0"), 10)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        start_angle_bg = 210 * 16
        span_angle_bg = -240 * 16
        painter.drawArc(gauge_rect, start_angle_bg, span_angle_bg)

        clamped_score = max(0.0, min(self.score, 10.0))
        
        # <-- DIUBAH: Warna gauge disesuaikan agar presisi dengan warna kategori
        if clamped_score >= 8: color = QColor("#D32F2F")      # Sangat Berbahaya (Merah)
        elif clamped_score >= 6: color = QColor("#F57C00")    # Berbahaya (Oranye)
        elif clamped_score >= 3: color = QColor("#FFC107")    # Mencurigakan (Kuning)
        else: color = QColor("#4CAF50")                       # Aman (Hijau)

        pen.setColor(color)
        painter.setPen(pen)
        score_span_angle = int((clamped_score / 10.0) * span_angle_bg)
        painter.drawArc(gauge_rect, start_angle_bg, score_span_angle)
        
        inner_rect = gauge_rect.adjusted(15, 15, -15, -15)
        painter.setBrush(QBrush(QColor("#FFFFFF")))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(inner_rect)

        score_text_rect = inner_rect.adjusted(0, -8, 0, -8)
        painter.setPen(QColor("#000000"))
        
        font_score = QFont("Arial", 26, QFont.Bold) 
        painter.setFont(font_score)
        painter.drawText(score_text_rect, Qt.AlignCenter, f"{clamped_score:.1f}")

        font_label = QFont("Arial", 11)
        painter.setFont(font_label)
        # <-- DIUBAH: Posisi label "Score" digeser lebih ke bawah
        label_rect = score_text_rect.adjusted(0, 42, 0, 0)
        painter.drawText(label_rect, Qt.AlignCenter, "Score")

        font_ends = QFont("Arial", 10)
        painter.setFont(font_ends)
        painter.drawText(int(gauge_rect.left()) - 5, int(gauge_rect.bottom()) + 5, "0")
        painter.drawText(int(gauge_rect.right()) - 5, int(gauge_rect.bottom()) + 5, "10")
        
        painter.end()


class ResultSummaryWidget(QWidget):
    def __init__(self, on_restart_analysis, parent=None):
        super().__init__(parent)
        self.on_restart_analysis = on_restart_analysis
        self.setStyleSheet("background-color: #3C3C3C;")
        self.pdf_path = None
        self.initUI()

    def initUI(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(25, 25, 25, 25)
        content_layout = QHBoxLayout()
        button_layout = QHBoxLayout()

        left_panel = QFrame()
        left_panel.setStyleSheet("background-color: #F5F5F5; border-radius: 15px;")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(15, 15, 15, 15)
        
        title_gauge = QLabel("Skor Perilaku")
        title_gauge.setAlignment(Qt.AlignCenter)
        title_gauge.setStyleSheet("font-weight: bold; font-size: 16px; color: black; padding-top: 10px;") 
        
        self.gauge = GaugeWidget()
        
        self.categoryLabel = QLabel("Kategori : -")
        self.categoryLabel.setAlignment(Qt.AlignCenter)
        self.categoryLabel.setStyleSheet("""
            background-color: gray; color: white; font-weight: bold; font-size: 14px; 
            border-radius: 15px; padding: 8px 30px;
        """)
        
        left_layout.addWidget(title_gauge)
        left_layout.addWidget(self.gauge, alignment=Qt.AlignCenter)
        left_layout.addSpacing(10)
        left_layout.addWidget(self.categoryLabel, alignment=Qt.AlignCenter)
        left_layout.addStretch()

        right_panel = QFrame()
        right_panel.setStyleSheet("background-color: #F5F5F5; border-radius: 15px;")
        right_layout = QGridLayout(right_panel)
        right_layout.setContentsMargins(25, 15, 25, 15)
        
        title_details = QLabel("Keterangan Malware")
        title_details.setAlignment(Qt.AlignCenter)
        title_details.setStyleSheet("font-weight: bold; font-size: 16px; color: black; padding-top: 10px; padding-bottom: 15px;")
        right_layout.addWidget(title_details, 0, 0, 1, 2)
        
        # <-- DIUBAH: "Task ID" menjadi "File ID", "Waktu Analisis" menjadi "Periode"
        self.fields = {
            "Jenis": QLabel("-"), "Nama": QLabel("-"), "Ukuran": QLabel("-"),
            "File ID": QLabel("-"), "Kategori": QLabel("-"),
            "Periode": QLabel("-"), "Lingkungan": QLabel("-")
        }
        
        row = 1
        for key, label in self.fields.items():
            key_lbl = QLabel(key)
            key_lbl.setStyleSheet("font-weight: bold; color: #333; font-size: 14px;")
            label.setWordWrap(True)
            label.setStyleSheet("color: black; font-size: 14px;")
            
            right_layout.addWidget(key_lbl, row, 0)
            right_layout.addWidget(label, row, 1, alignment=Qt.AlignRight)
            
            line = QFrame()
            line.setFrameShape(QFrame.HLine)
            line.setFrameShadow(QFrame.Sunken)
            line.setStyleSheet("color: #E0E0E0; margin-top: 5px; margin-bottom: 5px;")
            right_layout.addWidget(line, row + 1, 0, 1, 2)
            row += 2
        
        right_layout.setColumnStretch(1, 1)
        right_layout.setRowStretch(row, 1)

        content_layout.addWidget(left_panel, 1)
        content_layout.addSpacing(20)
        content_layout.addWidget(right_panel, 1)

        self.viewPdfButton = QPushButton("Lihat PDF")
        self.viewPdfButton.setMinimumHeight(45)
        self.viewPdfButton.setStyleSheet("QPushButton { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #00e676, stop:1 #00c853); color: White; padding: 10px; font-size: 14px; font-weight: bold; border-radius: 22px; } QPushButton:hover { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #69f0ae, stop:1 #00e676); }")
        
        self.restartButton = QPushButton("Analisa Ulang")
        self.restartButton.setMinimumHeight(45)
        self.restartButton.setStyleSheet("QPushButton { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #448AFF, stop:1 #2962FF); color: white; padding: 10px; font-size: 14px; font-weight: bold; border-radius: 22px; } QPushButton:hover { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #82B1FF, stop:1 #448AFF); }")

        self.viewPdfButton.clicked.connect(self.open_pdf)
        self.restartButton.clicked.connect(self.on_restart_analysis)

        button_layout.addWidget(self.viewPdfButton)
        button_layout.addWidget(self.restartButton)

        main_layout.addLayout(content_layout)
        main_layout.addSpacing(20)
        main_layout.addLayout(button_layout)
    
    def load_latest_report(self):
        json_path = self._find_latest_analysis_json()
        if not json_path: return
        try:
            with open(json_path, 'r') as f: data = json.load(f)
        except Exception as e:
            logging.error(f"Failed to load analysis.json: {e}")
            return

        score = data.get("score", 0.0)
        category = ("Sangat Berbahaya" if score >= 8 else "Berbahaya" if score >= 6 else "Mencurigakan" if score >= 3 else "Aman")
        predicted_family = self._read_ml_results()
        target = data.get("target", {})
        file_size = target.get("size", 0)
        ukuran = f"{file_size} bytes" if file_size else "-"

        # <-- DIUBAH: Mapping data ke field yang baru
        metadata = {
            "Jenis": predicted_family.title(), "Nama": target.get("filename", "-"),
            "Ukuran": ukuran, "File ID": data.get("id", "-"),
            "Kategori": category,
            "Periode": datetime.fromtimestamp(os.path.getmtime(json_path)).strftime('%Y-%m-%d %H:%M'),
            "Lingkungan": data.get("machine", {}).get("platform", "Windows") + " (Airgap)"
        }
        self.update_summary(score, category, metadata)
    
    def _read_ml_results(self):
        predicted_family = "-"
        if os.path.exists(ML_RESULT_PATH):
            try:
                with open(ML_RESULT_PATH, 'r') as f:
                    for line in f:
                        if line.startswith("Predicted family:"):
                            predicted_family = line.split(":", 1)[1].strip()
                            break
            except Exception as e: logging.error(f"Error reading ML_RESULT_PATH: {e}")
        return predicted_family

    def _find_latest_analysis_json(self):
        latest_file, latest_time = None, 0
        for root, _, files in os.walk(ANALYSIS_DIR_CUCKOO):
            if "analysis.json" in files:
                path = os.path.join(root, "analysis.json")
                mtime = os.path.getmtime(path)
                if mtime > latest_time:
                    latest_time, latest_file = mtime, path
        return latest_file

    def update_summary(self, score, category, metadata):
        self.gauge.set_score(score)
        self.categoryLabel.setText(f"Kategori : {category}")
        
        category_lower = category.lower()
        if "sangat berbahaya" in category_lower: style = "background-color: #D32F2F; color: white;"
        elif "berbahaya" in category_lower: style = "background-color: #F57C00; color: white;"
        elif "mencurigakan" in category_lower: style = "background-color: #FFC107; color: black;"
        else: style = "background-color: #4CAF50; color: white;"
        self.categoryLabel.setStyleSheet(f"{style} font-weight: bold; border-radius: 15px; padding: 8px 30px; font-size: 14px;")

        for key, label_widget in self.fields.items():
            value = metadata.get(key, "-")
            label_widget.setText(str(value))

    def open_pdf(self):
        if not self.pdf_path:
            pdf_files = [f for f in os.listdir(CUSTOM_PDF_REPORT_DIR) if f.endswith(".pdf")]
            if not pdf_files: return
            latest_pdf = max(pdf_files, key=lambda f: os.path.getmtime(os.path.join(CUSTOM_PDF_REPORT_DIR, f)))
            self.pdf_path = os.path.join(CUSTOM_PDF_REPORT_DIR, latest_pdf)

        if self.pdf_path and os.path.exists(self.pdf_path):
            try:
                if os.name == 'posix': os.system(f'xdg-open "{self.pdf_path}"')
                elif os.name == 'nt': os.startfile(self.pdf_path)
            except Exception as e: logging.error(f"Failed to open PDF: {e}")
