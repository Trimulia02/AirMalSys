import os
import logging
from datetime import datetime
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QStackedLayout, QGraphicsOpacityEffect
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation

from ui.loading import LoadingWidget
from ui.upload import UploadWidget
from ui.upload_success import UploadSuccessWidget
from ui.analysis_progress import AnalysisProgressWidget
from ui.report_summary import ResultSummaryWidget

import subprocess

LOG_FILE = "/home/cuckoo/TA_AnalisisMalware/Logs/ui_debug.log"
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class SetupThread(QThread):
    finished = pyqtSignal()
    def run(self):
        try:
            subprocess.call(["python3", "auto_start.py"])
            logging.info("SetupThread: auto_start.py dipanggil.")
        except Exception as e:
            logging.error(f"SetupThread: Gagal menjalankan auto_start.py: {e}")
        self.finished.emit()

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AirMalysis")
        self.setFixedSize(480, 340)
        self.setStyleSheet("background-color: #1e1e1e; color: white;")

        wrapper_layout = QVBoxLayout()
        wrapper_layout.setAlignment(Qt.AlignCenter)
        self.setLayout(wrapper_layout)

        self.stack = QStackedLayout()
        wrapper_layout.addLayout(self.stack)

        self.loading_widget    = LoadingWidget()
        self.upload_widget     = UploadWidget()
        self.upload_success    = UploadSuccessWidget()
        self.analysis_widget   = AnalysisProgressWidget(on_analysis_complete=self._safe_switch_to_summary, on_error=self.handle_analysis_error)
        self.report_summary    = ResultSummaryWidget(on_restart_analysis=self.switch_to_upload_after_rebuild)

        self.stack.addWidget(self.loading_widget)
        self.stack.addWidget(self.upload_widget)
        self.stack.addWidget(self.upload_success)
        self.stack.addWidget(self.analysis_widget)
        self.stack.addWidget(self.report_summary)

        self.stack.setCurrentWidget(self.loading_widget)

        self.thread = SetupThread()
        self.thread.finished.connect(self.show_upload_screen_after_loading)
        self.thread.start()
        logging.info("MainWindow initialized and SetupThread started.")

    def show_upload_screen_after_loading(self):
        logging.info("SetupThread selesai. Beralih ke UploadWidget.")
        if hasattr(self.upload_widget, 'reset_fields'):
            self.upload_widget.reset_fields()
        self.stack.setCurrentWidget(self.upload_widget)
        self.fade_in_widget(self.upload_widget)

    def handle_file_upload_success(self):
        logging.info("MainWindow: Menerima panggilan handle_file_upload_success.")
        self.fade_out_widget(self.upload_widget, self._show_and_fade_in_upload_success)

    def _show_and_fade_in_upload_success(self):
        logging.info("Menampilkan UploadSuccessWidget.")
        self.stack.setCurrentWidget(self.upload_success)
        self.fade_in_widget(self.upload_success)

        try:
            self.upload_success.start_timer(self.switch_to_analysis_progress)
        except Exception as e:
            logging.error(f"Gagal memulai timer upload_success: {e}")

    def switch_to_analysis_progress(self):
        logging.info("📡 switch_to_analysis_progress() aktif dari UploadSuccessWidget.")
        try:
            self.analysis_widget.analysis_started_at = datetime.now()
            self.analysis_widget.last_report_path = self.analysis_widget.find_latest_report_json()
            self.analysis_widget.progress.setValue(0)
            self.analysis_widget.label.setText("📜 Analyzing...\nPlease Wait...")

            if hasattr(self.analysis_widget, 'movie') and self.analysis_widget.movie.isValid():
                self.analysis_widget.movie.start()

            if self.analysis_widget.timer.isActive():
                self.analysis_widget.timer.stop()
            self.analysis_widget.timer.start(1000)

            self.fade_out_widget(self.upload_success, self._show_and_fade_in_analysis_progress)
        except Exception as e:
            logging.error(f"Error dalam switch_to_analysis_progress: {e}", exc_info=True)

    def _show_and_fade_in_analysis_progress(self):
        logging.info("Menampilkan AnalysisProgressWidget.")
        self.stack.setCurrentWidget(self.analysis_widget)
        self.fade_in_widget(self.analysis_widget)

    def _safe_switch_to_summary(self):
        logging.info("MainWindow: Menerima panggilan _safe_switch_to_summary.")
        self.fade_out_widget(self.analysis_widget, self.show_report_summary_screen)

    def show_report_summary_screen(self):
        try:
            self.setFixedSize(720, 460)
            self.report_summary.load_latest_report()
            self.stack.setCurrentWidget(self.report_summary)
            self.fade_in_widget(self.report_summary)
            logging.info("Berhasil beralih ke ReportSummaryWidget.")
        except Exception as e:
            logging.error(f"MainWindow: Error saat beralih ke ReportSummaryWidget: {e}", exc_info=True)

    def switch_to_upload_after_rebuild(self):
        logging.info("MainWindow: Menerima panggilan switch_to_upload_after_rebuild.")
        self.setFixedSize(480, 340)
        self.fade_out_widget(self.report_summary, self.rebuild_core_widgets_and_show_upload)

    def handle_analysis_error(self):
        logging.error("Analysis failed or timeout. Returning to upload page.")
        self.setFixedSize(480, 340)
        self.stack.setCurrentWidget(self.upload_widget)
        if hasattr(self.upload_widget, 'show_error_message'):
            self.upload_widget.show_error_message("Analysis failed or took too long. Please try again.")

    def rebuild_core_widgets_and_show_upload(self):
        logging.info("🔁 Membangun ulang widget inti...")

        self.stack.removeWidget(self.upload_widget)
        self.upload_widget.deleteLater()
        self.upload_widget = UploadWidget()
        self.stack.insertWidget(1, self.upload_widget)

        self.stack.removeWidget(self.analysis_widget)
        self.analysis_widget.deleteLater()
        self.analysis_widget = AnalysisProgressWidget(on_analysis_complete=self._safe_switch_to_summary, on_error=self.handle_analysis_error)
        self.stack.insertWidget(3, self.analysis_widget)

        self.stack.setCurrentWidget(self.upload_widget)
        self.fade_in_widget(self.upload_widget)
        logging.info("✅ Widget inti telah dibangun ulang. Tampilan saat ini: UploadWidget.")

    def fade_in_widget(self, widget, duration=300):
        if widget is None: return
        try:
            effect = QGraphicsOpacityEffect(widget)
            widget.setGraphicsEffect(effect)
            anim = QPropertyAnimation(effect, b"opacity", widget)
            anim.setDuration(duration)
            anim.setStartValue(0.0)
            anim.setEndValue(1.0)
            anim.finished.connect(lambda: widget.setGraphicsEffect(None) if effect == widget.graphicsEffect() else None)
            anim.start(QPropertyAnimation.DeleteWhenStopped)
        except Exception as e:
            logging.error(f"MainWindow: Gagal fade_in_widget untuk {widget}: {e}")

    def fade_out_widget(self, widget, on_finished_callback=None, duration=300):
        if widget is None:
            if on_finished_callback:
                on_finished_callback()
            return
        try:
            effect = QGraphicsOpacityEffect(widget)
            widget.setGraphicsEffect(effect)
            anim = QPropertyAnimation(effect, b"opacity", widget)
            anim.setDuration(duration)
            anim.setStartValue(1.0)
            anim.setEndValue(0.0)

            if on_finished_callback:
                anim.finished.connect(on_finished_callback)

            current_effect = widget.graphicsEffect()
            anim.finished.connect(lambda: widget.setGraphicsEffect(None) if widget.graphicsEffect() == current_effect else None)
            anim.start(QPropertyAnimation.DeleteWhenStopped)
        except Exception as e:
            logging.error(f"MainWindow: Gagal fade_out_widget untuk {widget}: {e}")