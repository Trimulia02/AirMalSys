from PyQt5.QtWidgets import QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QGridLayout
from PyQt5.QtGui import QFont, QPainter, QPen, QColor
from PyQt5.QtCore import Qt
import os
import logging
import json
from datetime import datetime

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
        try:
            self.score = float(score)
        except (ValueError, TypeError):
            logging.warning(f"GaugeWidget: Invalid score '{score}', set to 0.0.")
            self.score = 0.0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect()
        center = rect.center()
        radius = min(rect.width(), rect.height()) / 2 - 20
        x = int(center.x() - radius)
        y = int(center.y() - radius)
        w = h = int(2 * radius)

        painter.setPen(QPen(Qt.gray, 20))
        painter.drawArc(x, y, w, h, 45 * 16, 270 * 16)

        clamped_score = max(0.0, min(self.score, 10.0))
        angle_span = int((clamped_score / 10.0) * 270)
        color = Qt.darkGray
        if clamped_score >= 8:
            color = Qt.red
        elif clamped_score >= 6:
            color = QColor(255, 165, 0)
        elif clamped_score >= 3:
            color = Qt.yellow
        else:
            color = Qt.green

        painter.setPen(QPen(color, 20))
        painter.drawArc(x, y, w, h, (45 + 270 - angle_span) * 16, angle_span * 16)

        painter.setPen(Qt.white)
        font = QFont("Arial", 16, QFont.Bold)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignCenter, f"{clamped_score:.1f}\nScore")
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
        title_gauge = QLabel("Behavior Score")
        title_gauge.setAlignment(Qt.AlignCenter)
        title_gauge.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.gauge = GaugeWidget()
        self.categoryLabel = QLabel("Category: -")
        self.categoryLabel.setAlignment(Qt.AlignCenter)
        self.categoryLabel.setFixedHeight(40)
        self.categoryLabel.setStyleSheet("""
            background-color: gray;
            color: white;
            font-weight: bold;
            font-size: 14px;
            padding: 8px;
            border-radius: 12px;
        """)
        left_frame.addWidget(title_gauge)
        left_frame.addWidget(self.gauge, alignment=Qt.AlignCenter)
        left_frame.addWidget(self.categoryLabel, alignment=Qt.AlignCenter)
        left_frame.addStretch()

        right_frame = QGridLayout()
        title = QLabel("Malware Details")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        right_frame.addWidget(title, 0, 0, 1, 2)

        self.fields = {
            "Type": QLabel("-"), "Filename": QLabel("-"), "Size": QLabel("-"),
            "Task ID": QLabel("-"), "Category": QLabel("-"),
            "Analysis Time": QLabel("-"), "Environment": QLabel("-")
        }
        for i, (key, label) in enumerate(self.fields.items()):
            key_lbl = QLabel(key)
            key_lbl.setStyleSheet("font-weight: bold;")
            label.setStyleSheet("color: white;")
            right_frame.addWidget(key_lbl, i + 1, 0)
            right_frame.addWidget(label, i + 1, 1)

        content_layout.addLayout(left_frame, 1)
        content_layout.addLayout(right_frame, 2)

        self.viewPdfButton = QPushButton("Open PDF")
        self.viewPdfButton.setStyleSheet("""
            background-color: #00e676;
            color: black;
            padding: 10px;
            font-weight: bold;
            border-radius: 8px;
        """)
        self.viewPdfButton.clicked.connect(self.open_pdf)

        self.restartButton = QPushButton("Reanalyze")
        self.restartButton.setStyleSheet("""
            background-color: #2979ff;
            color: white;
            padding: 10px;
            font-weight: bold;
            border-radius: 8px;
        """)
        self.restartButton.clicked.connect(self.on_restart_analysis)

        button_layout.addWidget(self.viewPdfButton)
        button_layout.addWidget(self.restartButton)

        main_layout.addLayout(content_layout)
        main_layout.addSpacing(20)
        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

    def _read_ml_results(self):
        predicted_family = "-"
        if os.path.exists(ML_RESULT_PATH):
            try:
                with open(ML_RESULT_PATH, 'r') as f:
                    for line in f:
                        if line.startswith("Predicted family:"):
                            predicted_family = line.split(":", 1)[1].strip()
                            break
            except Exception as e:
                logging.error(f"Error reading ML_RESULT_PATH: {e}")
        return predicted_family

    def _find_latest_analysis_json(self):
        latest_file = None
        latest_time = 0
        for root, _, files in os.walk(ANALYSIS_DIR_CUCKOO):
            if "analysis.json" in files:
                path = os.path.join(root, "analysis.json")
                mtime = os.path.getmtime(path)
                if mtime > latest_time:
                    latest_time = mtime
                    latest_file = path
        return latest_file

    def load_latest_report(self):
        json_path = self._find_latest_analysis_json()
        if not json_path:
            logging.warning("No analysis.json found.")
            return

        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logging.error(f"Failed to load analysis.json: {e}")
            return

        score = data.get("score", 0.0)
        category = (
            "Very Dangerous" if score >= 8 else
            "Dangerous" if score >= 6 else
            "Suspicious" if score >= 3 else
            "Not Dangerous"
        )

        predicted_family = self._read_ml_results()

        target = data.get("target", {})
        file_size = target.get("size", 0)
        ukuran = f"{file_size / 1024:.2f} KB" if file_size else "-"

        metadata = {
            "Type": predicted_family.upper(),
            "Filename": target.get("filename", "-"),
            "Size": ukuran,
            "Task ID": data.get("id", "-"),
            "Category": category,
            "Analysis Time": datetime.fromtimestamp(os.path.getmtime(json_path)).strftime('%Y-%m-%d %H:%M:%S'),
            "Environment": data.get("machine", {}).get("platform", "Windows") + " (Sandbox)"
        }

        self.update_summary(score, category, metadata)

    def update_summary(self, score, category, metadata):
        self.gauge.set_score(score)
        self.categoryLabel.setText(f"Category: {category}")
        category_lower = category.lower()
        if "very dangerous" in category_lower:
            self.categoryLabel.setStyleSheet("background-color: #c00000; color: white; font-weight: bold; padding: 8px; border-radius: 12px;")
        elif "dangerous" in category_lower:
            self.categoryLabel.setStyleSheet("background-color: #ff8c00; color: white; font-weight: bold; padding: 8px; border-radius: 12px;")
        elif "suspicious" in category_lower:
            self.categoryLabel.setStyleSheet("background-color: #ffc107; color: black; font-weight: bold; padding: 8px; border-radius: 12px;")
        else:
            self.categoryLabel.setStyleSheet("background-color: #28a745; color: white; font-weight: bold; padding: 8px; border-radius: 12px;")

        for key, label_widget in self.fields.items():
            value = metadata.get(key, "-")
            if key == "Type":
                label_widget.setText(value.upper())
                if value.upper() == "MALWARE":
                    label_widget.setStyleSheet("color: red; font-weight: bold;")
                elif value.upper() == "BENIGN":
                    label_widget.setStyleSheet("color: green; font-weight: bold;")
                else:
                    label_widget.setStyleSheet("color: white;")
            else:
                label_widget.setText(str(value))

    def open_pdf(self):
        if not self.pdf_path:
            pdf_files = [f for f in os.listdir(CUSTOM_PDF_REPORT_DIR) if f.endswith(".pdf")]
            if not pdf_files:
                logging.warning("No PDF found in report directory.")
                return
            latest_pdf = max(
                pdf_files,
                key=lambda f: os.path.getmtime(os.path.join(CUSTOM_PDF_REPORT_DIR, f))
            )
            self.pdf_path = os.path.join(CUSTOM_PDF_REPORT_DIR, latest_pdf)

        if self.pdf_path and os.path.exists(self.pdf_path):
            try:
                if os.name == 'posix':
                    os.system(f'xdg-open "{self.pdf_path}"')
                elif os.name == 'nt':
                    os.startfile(self.pdf_path)
            except Exception as e:
                logging.error(f"Failed to open PDF: {e}")
