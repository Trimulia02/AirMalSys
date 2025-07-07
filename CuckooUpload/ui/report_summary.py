from PyQt5.QtWidgets import QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QGridLayout, QFrame
from PyQt5.QtGui import QFont, QPainter, QPen, QColor, QBrush
from PyQt5.QtCore import Qt, QRectF
import os
import logging
import json
from datetime import datetime
import subprocess
import threading
import time

ANALYSIS_DIR_CUCKOO = "/home/cuckoo/.cuckoocwd/storage/analyses"
CUSTOM_PDF_REPORT_DIR = "/home/cuckoo/TA_AnalisisMalware/Report"
ML_RESULT_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/ml_results.txt"
CVSS_SCORE_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/cvss_score.txt"
CVSS_CALCULATOR_PATH = "/home/cuckoo/TA_AnalisisMalware/reportModule/cvss_calculator.py"
INFERENCE_PATH = "/home/cuckoo/TA_AnalisisMalware/resultML/inference.py"
VENV_PYTHON = "/home/cuckoo/TA_AnalisisMalware/resultML/venv/bin/python"
ARTIFACTS_DIR = "/home/cuckoo/TA_AnalisisMalware/resultML/artifacts"


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
        painter.drawArc(gauge_rect, 210 * 16, -240 * 16)

        clamped_score = max(0.0, min(self.score, 10.0))
        if clamped_score >= 8:
            color = QColor("#D32F2F")
        elif clamped_score >= 6:
            color = QColor("#F57C00")
        elif clamped_score >= 3:
            color = QColor("#FFC107")
        else:
            color = QColor("#4CAF50")

        pen.setColor(color)
        painter.setPen(pen)
        span_angle = int((clamped_score / 10.0) * -240 * 16)
        painter.drawArc(gauge_rect, 210 * 16, span_angle)

        inner_rect = gauge_rect.adjusted(15, 15, -15, -15)
        painter.setBrush(QBrush(QColor("#FFFFFF")))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(inner_rect)

        painter.setPen(QColor("#000000"))
        font_score = QFont("Arial", 26, QFont.Bold)
        painter.setFont(font_score)
        painter.drawText(inner_rect.adjusted(0, -8, 0, -8), Qt.AlignCenter, f"{clamped_score:.1f}")

        font_label = QFont("Arial", 11)
        painter.setFont(font_label)
        painter.drawText(inner_rect.adjusted(0, 42, 0, 0), Qt.AlignCenter, "Score")

        font_ends = QFont("Arial", 10)
        painter.setFont(font_ends)
        painter.drawText(int(gauge_rect.left()) - 5, int(gauge_rect.bottom()) + 5, "0")
        painter.drawText(int(gauge_rect.right()) - 5, int(gauge_rect.bottom()) + 5, "10")


class ResultSummaryWidget(QWidget):
    def __init__(self, on_restart_analysis, parent=None):
        super().__init__(parent)
        self.on_restart_analysis = on_restart_analysis
        self.setStyleSheet("background-color: #3C3C3C;")
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
        title_gauge.setStyleSheet("font-weight: bold; font-size: 15px; color: black; padding-top: 10px;")
        self.gauge = GaugeWidget()
        self.categoryLabel = QLabel("Kategori : -")
        self.categoryLabel.setAlignment(Qt.AlignCenter)
        self.categoryLabel.setStyleSheet("background-color: gray; color: white; font-weight: bold; font-size: 14px; border-radius: 15px; padding: 8px 30px;")

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
        title_details.setStyleSheet("font-weight: bold; font-size: 15px; color: black; padding-top: 13px; padding-bottom: 15px;")
        right_layout.addWidget(title_details, 0, 0, 1, 2)

        self.fields = {
            "Jenis": QLabel("-"),
            "Family": QLabel("-"),
            "Confidence": QLabel("-"),
            "Nama": QLabel("-"),
            "Ukuran": QLabel("-"),
            "File ID": QLabel("-"),
            "Kategori": QLabel("-"),
            "Periode": QLabel("-"),
            "Lingkungan": QLabel("-")
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

        content_layout.addWidget(left_panel, 1)
        content_layout.addSpacing(20)
        content_layout.addWidget(right_panel, 1)

        self.viewPdfButton = QPushButton("Lihat PDF")
        self.viewPdfButton.setMinimumHeight(45)
        self.viewPdfButton.setStyleSheet("QPushButton { background-color: #00c853; color: white; font-size: 14px; font-weight: bold; border-radius: 22px; } QPushButton:hover { background-color: #00e676; }")
        self.restartButton = QPushButton("Analisa Ulang")
        self.restartButton.setMinimumHeight(45)
        self.restartButton.setStyleSheet("QPushButton { background-color: #2962FF; color: white; font-size: 14px; font-weight: bold; border-radius: 22px; } QPushButton:hover { background-color: #448AFF; }")

        self.viewPdfButton.clicked.connect(self.open_pdf)
        self.restartButton.clicked.connect(self.on_restart_analysis)

        button_layout.addWidget(self.viewPdfButton)
        button_layout.addWidget(self.restartButton)

        main_layout.addLayout(content_layout)
        main_layout.addSpacing(20)
        main_layout.addLayout(button_layout)

    def load_latest_report(self):
        thread = threading.Thread(target=self._run_analysis_pipeline)
        thread.start()

    def _run_analysis_pipeline(self):
        try:
            subprocess.run(["python3", CVSS_CALCULATOR_PATH], check=True)
        except Exception as e:
            logging.error(f"Gagal menjalankan CVSS calculator: {e}")
            return

        report_path = self._find_latest_report_json()
        if not report_path:
            logging.error("❌ Tidak ada report.json ditemukan.")
            return

        try:
            subprocess.run([
                VENV_PYTHON, INFERENCE_PATH,
                "--report", report_path,
                "--artifacts", ARTIFACTS_DIR,
                "--output", ML_RESULT_PATH
            ], check=True)
        except Exception as e:
            logging.error(f"Gagal menjalankan inference: {e}")
            return

        for _ in range(10):
            if os.path.exists(ML_RESULT_PATH) and os.path.getsize(ML_RESULT_PATH) > 0:
                break
            time.sleep(0.5)

        score = self._read_cvss_score()
        category = "Sangat Berbahaya" if score >= 8 else "Berbahaya" if score >= 6 else "Mencurigakan" if score >= 3 else "Aman"
        predicted_family, confidence, jenis = self._read_ml_results()

        # Cari analysis.json
        analysis_json_path = os.path.join(os.path.dirname(os.path.dirname(report_path)), "analysis.json")
        filename = "-"
        ukuran = "-"
        file_id = "-"

        if os.path.exists(analysis_json_path):
            try:
                with open(analysis_json_path, 'r') as f:
                    analysis_data = json.load(f)
                    target = analysis_data.get("target", {})
                    filename = target.get("filename", "-")
                    ukuran = f"{target.get('size', 0)} bytes" if target.get("size") else "-"
                    file_id = analysis_data.get("id", "-")
            except Exception as e:
                logging.error(f"Gagal membaca analysis.json: {e}")

        metadata = {
            "Jenis": jenis,
            "Family": predicted_family,
            "Confidence": f"{confidence:.1f}%" if confidence else "-",
            "Nama": filename,
            "Ukuran": ukuran,
            "File ID": file_id,
            "Kategori": category,
            "Periode": datetime.fromtimestamp(os.path.getmtime(report_path)).strftime('%Y-%m-%d %H:%M'),
            "Lingkungan": "Windows (Airgap)"
        }

        self.update_summary(score, category, metadata)

    def _find_latest_report_json(self):
        latest_file = None
        latest_time = 0
        for root, _, files in os.walk(ANALYSIS_DIR_CUCKOO):
            if "report.json" in files:
                path = os.path.join(root, "report.json")
                mtime = os.path.getmtime(path)
                if mtime > latest_time:
                    latest_time = mtime
                    latest_file = path
        return latest_file

    def _read_cvss_score(self):
        try:
            with open(CVSS_SCORE_PATH, 'r') as f:
                return float(f.read().strip())
        except Exception:
            return 0.0

    def _read_ml_results(self):
        predicted_family = "-"
        confidence = None
        jenis = "-"
        if os.path.exists(ML_RESULT_PATH):
            try:
                with open(ML_RESULT_PATH, 'r') as f:
                    lines = [line.strip() for line in f.readlines()]
                    if lines:
                        status = lines[0].lower()
                        if status == "malware" and len(lines) >= 3:
                            predicted_family = lines[2]
                            confidence = float(lines[1]) * 100
                            jenis = "Malware"
                        elif status == "benign":
                            predicted_family = "Benign"
                            confidence = float(lines[1]) * 100
                            jenis = "Benign"
            except Exception as e:
                logging.error(f"Error reading ML_RESULT_PATH: {e}")
        return predicted_family, confidence, jenis

    def update_summary(self, score, category, metadata):
        self.gauge.set_score(score)
        self.categoryLabel.setText(f"Kategori : {category}")
        color_map = {
            "Sangat Berbahaya": "#D32F2F",
            "Berbahaya": "#F57C00",
            "Mencurigakan": "#FFC107",
            "Aman": "#4CAF50"
        }
        bg_color = color_map.get(category, "gray")
        fg_color = "white" if category != "Mencurigakan" else "black"
        self.categoryLabel.setStyleSheet(f"background-color: {bg_color}; color: {fg_color}; font-weight: bold; border-radius: 15px; padding: 8px 30px; font-size: 14px;")

        for key, label_widget in self.fields.items():
            label_widget.setText(str(metadata.get(key, "-")))

    def open_pdf(self):
        try:
            subprocess.run(["python3", "/home/cuckoo/TA_AnalisisMalware/reportModule/report_generator.py"], check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Gagal menjalankan report_generator.py: {e}")
            return

        pdf_files = [f for f in os.listdir(CUSTOM_PDF_REPORT_DIR) if f.endswith(".pdf")]
        if not pdf_files:
            logging.error("Tidak ada file PDF ditemukan.")
            return

        latest_pdf = max(pdf_files, key=lambda f: os.path.getmtime(os.path.join(CUSTOM_PDF_REPORT_DIR, f)))
        latest_path = os.path.join(CUSTOM_PDF_REPORT_DIR, latest_pdf)

        try:
            os.system(f'xdg-open "{latest_path}"')
        except Exception as e:
            logging.error(f"Gagal membuka PDF: {e}")

    def refresh(self):
        self.load_latest_report()
