import os
import glob
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QProgressBar, QPushButton, QGraphicsOpacityEffect
)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation
from PyQt5.QtGui import QMovie

class AnalysisProgressWidget(QWidget):
    def __init__(self, on_analysis_complete=None):
        super().__init__()
        self.on_analysis_complete = on_analysis_complete
        self.report_dir = "/home/cuckoo/TA_AnalisisMalware/Report"

        self.setStyleSheet("""
            QProgressBar {
                height: 20px;
                border-radius: 10px;
                background-color: #2c2c2c;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #00c853;
                border-radius: 10px;
            }
            QPushButton {
                background-color: #2962ff;
                color: white;
                padding: 8px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0039cb;
            }
        """)

        self.gif_label = QLabel()
        self.gif_label.setFixedSize(200, 200)
        self.gif_label.setScaledContents(True)
        self.gif_label.setAlignment(Qt.AlignCenter)

        gif_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../assets/loading4.gif"))
        self.movie = QMovie(gif_path)
        if os.path.exists(gif_path) and self.movie.isValid():
            self.gif_label.setMovie(self.movie)
            self.movie.start()
        else:
            self.gif_label.setText("⏳")

        gif_container = QHBoxLayout()
        gif_container.addStretch()
        gif_container.addWidget(self.gif_label)
        gif_container.addStretch()

        self.label = QLabel("📜 Melakukan analisis...\nSilakan tunggu...")
        self.label.setAlignment(Qt.AlignCenter)

        self.progress = QProgressBar()
        self.progress.setMaximum(100)
        self.progress.setValue(0)

        self.open_button = QPushButton("📄 Lihat Laporan PDF")
        self.open_button.setVisible(False)

        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.addLayout(gif_container)
        layout.addWidget(self.label)
        layout.addWidget(self.progress)
        layout.addWidget(self.open_button)
        self.setLayout(layout)

        self.analysis_started_at = datetime.now()
        self.last_report_path = self.get_latest_report_path()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)
        self.timer.start(1000)

        self.effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.effect)
        self.anim = QPropertyAnimation(self.effect, b"opacity")
        self.anim.setDuration(800)
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.start()

    def get_latest_report_path(self):
        pdfs = glob.glob(os.path.join(self.report_dir, "*.pdf"))
        return max(pdfs, key=os.path.getmtime) if pdfs else None

    def update_progress(self):
        value = self.progress.value()
        new_report = self.get_latest_report_path()

        if new_report:
            report_mtime = datetime.fromtimestamp(os.path.getmtime(new_report))
            if (not self.last_report_path or new_report != self.last_report_path) and report_mtime > self.analysis_started_at:
                self.progress.setValue(100)
                self.label.setText("✅ Analisis selesai. Menampilkan ringkasan...")
                self.timer.stop()
                self.last_report_path = new_report
                print("🟢 on_analysis_complete() dipanggil dari AnalysisProgressWidget")
                if self.on_analysis_complete:
                    print("🟢 on_analysis_complete() dipanggil dari AnalysisProgressWidget")
                    QTimer.singleShot(1200, self.on_analysis_complete)
                else:
                    print("🔴 on_analysis_complete tidak ter-set")


        if value < 97:
            self.progress.setValue(value + 1)