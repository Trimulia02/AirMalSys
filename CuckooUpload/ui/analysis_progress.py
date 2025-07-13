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
    def __init__(self, on_analysis_complete=None, on_error=None):
        super().__init__()
        self.on_analysis_complete = on_analysis_complete
        self.on_error = on_error
        self.analysis_started_at = datetime.now()
        self.downtime_timer = None
        self.downtime_active = False

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

        self.label = QLabel("📜 Analyzing...\nPlease Wait...")
        self.label.setAlignment(Qt.AlignCenter)

        self.progress = QProgressBar()
        self.progress.setMaximum(100)
        self.progress.setValue(6)

        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.addLayout(gif_container)
        layout.addWidget(self.label)
        layout.addWidget(self.progress)
        self.setLayout(layout)

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

    def find_latest_report_json(self):
        base_dir = "/home/cuckoo/.cuckoocwd/storage/analyses"
        pattern = os.path.join(base_dir, "*", "*", "task_1", "report.json")
        files = glob.glob(pattern)
        if not files:
            return None
        return max(files, key=os.path.getmtime)

    def start_downtime(self):
        if self.downtime_active:
            return
        self.downtime_active = True
        self.label.setText("⏳ Analysis is taking longer than usual. Waiting up to 3 minutes...")
        self.downtime_timer = QTimer(self)
        self.downtime_timer.setSingleShot(True)
        self.downtime_timer.timeout.connect(self.handle_downtime_timeout)
        self.downtime_timer.start(180000)  # 3 minutes

    def stop_downtime(self):
        if self.downtime_timer:
            self.downtime_timer.stop()
            self.downtime_timer = None
        self.downtime_active = False

    def handle_downtime_timeout(self):
        self.timer.stop()
        self.label.setText("❌ Error: Analysis failed or took too long. Returning to upload page...")
        if self.on_error:
            QTimer.singleShot(1500, self.on_error)
        else:
            print("[ERROR] on_error callback not set!")

    def update_progress(self):
        value = self.progress.value()

        # Pastikan progress tidak pernah kurang dari 6
        if value < 6:
            self.progress.setValue(6)
            value = 6

        latest_report = self.find_latest_report_json()
        if latest_report and os.path.getmtime(latest_report) > self.analysis_started_at.timestamp():
            self.stop_downtime()
            self.progress.setValue(100)
            self.label.setText("✅ Analysis Completed. Showing Report Summary...")
            self.timer.stop()
            print("🟢 on_analysis_complete() dipanggil dari AnalysisProgressWidget")
            if self.on_analysis_complete:
                QTimer.singleShot(1200, self.on_analysis_complete)
            else:
                print("🔴 on_analysis_complete tidak ter-set")
            return

        if value < 97:
            self.progress.setValue(value + 1)
        elif value == 97:
            self.start_downtime()