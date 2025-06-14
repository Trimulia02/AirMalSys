# main_window.py

import os
import logging
from datetime import datetime
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QStackedLayout, QGraphicsOpacityEffect
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QTimer
# Pastikan path ke modul UI sudah benar sesuai struktur proyek Anda
from ui.loading import LoadingWidget
from ui.upload import UploadWidget
from ui.upload_success import UploadSuccessWidget
from ui.analysis_progress import AnalysisProgressWidget
from ui.report_summary import ResultSummaryWidget
import subprocess

LOG_FILE = "/home/cuckoo/TA_AnalisisMalware/Logs/ui_debug.log" # Sesuaikan path jika perlu
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class SetupThread(QThread):
    finished = pyqtSignal()
    def run(self):
        try:
            # Pastikan 'auto_start.py' ada dan dapat dieksekusi, atau sesuaikan path jika perlu
            subprocess.call(["python3", "auto_start.py"])
            logging.info("SetupThread: auto_start.py dipanggil.")
        except Exception as e:
            logging.error(f"SetupThread: Gagal menjalankan auto_start.py: {e}")
        self.finished.emit()

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AirMalysis")
        self.setFixedSize(480, 340) # Ukuran window utama
        self.setStyleSheet("background-color: #1e1e1e; color: white;")

        wrapper_layout = QVBoxLayout()
        wrapper_layout.setAlignment(Qt.AlignCenter)
        self.setLayout(wrapper_layout)

        self.stack = QStackedLayout()
        wrapper_layout.addLayout(self.stack)

        # Inisialisasi semua widget tampilan
        self.loading_widget    = LoadingWidget()
        self.upload_widget     = UploadWidget()
        self.upload_success    = UploadSuccessWidget()
        self.analysis_widget   = AnalysisProgressWidget(on_analysis_complete=self._safe_switch_to_summary)
        self.report_summary    = ResultSummaryWidget(on_restart_analysis=self.switch_to_upload_after_rebuild)

        # Tambahkan widget ke QStackedLayout
        self.stack.addWidget(self.loading_widget)     # index 0
        self.stack.addWidget(self.upload_widget)      # index 1
        self.stack.addWidget(self.upload_success)     # index 2
        self.stack.addWidget(self.analysis_widget)    # index 3
        self.stack.addWidget(self.report_summary)     # index 4

        self.stack.setCurrentWidget(self.loading_widget) # Tampilan awal adalah loading

        # Thread untuk setup awal (jika ada)
        self.thread = SetupThread()
        self.thread.finished.connect(self.show_upload_screen_after_loading)
        self.thread.start()
        logging.info("MainWindow initialized and SetupThread started.")

    def show_upload_screen_after_loading(self):
        logging.info("SetupThread selesai. Beralih ke UploadWidget.")
        if hasattr(self.upload_widget, 'reset_fields') and callable(self.upload_widget.reset_fields):
            self.upload_widget.reset_fields()
        self.stack.setCurrentWidget(self.upload_widget)
        self.fade_in_widget(self.upload_widget)

    # Dipanggil dari UploadWidget (via self.window().handle_file_upload_success())
    def handle_file_upload_success(self):
        logging.info("MainWindow: Menerima panggilan handle_file_upload_success. Beralih ke UploadSuccessWidget.")
        print("MainWindow: handle_file_upload_success() DIPANGGIL.")
        self.fade_out_widget(self.upload_widget, self._show_and_fade_in_upload_success)

    def _show_and_fade_in_upload_success(self):
        self.stack.setCurrentWidget(self.upload_success)
        self.fade_in_widget(self.upload_success)
        logging.info("UploadSuccessWidget ditampilkan.")
        # UploadSuccessWidget memiliki QTimer internal yang akan memanggil switch_to_analysis_progress

    # Dipanggil dari UploadSuccessWidget (via self.window().switch_to_analysis_progress())
    def switch_to_analysis_progress(self):
        logging.info("MainWindow: Menerima panggilan switch_to_analysis_progress. Beralih ke AnalysisProgressWidget.")
        print("MainWindow: switch_to_analysis_progress() DIPANGGIL.")
        if self.analysis_widget:
            self.analysis_widget.analysis_started_at = datetime.now()
            self.analysis_widget.last_report_path = self.analysis_widget.get_latest_report_path()
            self.analysis_widget.progress.setValue(0)
            self.analysis_widget.label.setText("📜 Melakukan analisis...\nSilakan tunggu...")
            if hasattr(self.analysis_widget, 'movie') and self.analysis_widget.movie and self.analysis_widget.movie.isValid():
                self.analysis_widget.movie.stop()
                self.analysis_widget.movie.start()
            
            if self.analysis_widget.timer.isActive():
                self.analysis_widget.timer.stop()
            self.analysis_widget.timer.start(1000)
            
            self.fade_out_widget(self.upload_success, self._show_and_fade_in_analysis_progress)
            logging.info("AnalysisProgressWidget disiapkan.")
        else:
            logging.error("MainWindow: AnalysisProgressWidget belum diinisialisasi!")
            print("MainWindow: ERROR - AnalysisProgressWidget belum diinisialisasi!")

    def _show_and_fade_in_analysis_progress(self):
        self.stack.setCurrentWidget(self.analysis_widget)
        self.fade_in_widget(self.analysis_widget)
        logging.info("AnalysisProgressWidget ditampilkan.")

    # Callback dari AnalysisProgressWidget setelah analisis selesai
    def _safe_switch_to_summary(self):
        logging.info("MainWindow: Menerima panggilan _safe_switch_to_summary dari AnalysisProgressWidget.")
        print("MainWindow: _safe_switch_to_summary() DIPANGGIL.")
        # Mulai animasi fade-out untuk AnalysisProgressWidget, lalu panggil show_report_summary_screen
        self.fade_out_widget(self.analysis_widget, self.show_report_summary_screen)

    def show_report_summary_screen(self):
        try:
            self.report_summary.load_latest_report()
            self.stack.setCurrentWidget(self.report_summary)
            self.fade_in_widget(self.report_summary) # Tampilkan ResultSummaryWidget dengan fade-in
            logging.info("Berhasil beralih ke ReportSummaryWidget dengan animasi fade.")
        except Exception as e:
            logging.error(f"MainWindow: Error saat beralih ke ReportSummaryWidget: {e}", exc_info=True)
            print(f"MainWindow: Error saat beralih ke ReportSummaryWidget: {e}")

    # Dipanggil dari tombol "Analisa Ulang" di ResultSummaryWidget
    def switch_to_upload_after_rebuild(self):
        logging.info("MainWindow: Menerima panggilan switch_to_upload_after_rebuild. Membangun ulang widget.")
        print("MainWindow: switch_to_upload_after_rebuild() DIPANGGIL.")
        self.fade_out_widget(self.report_summary, self.rebuild_core_widgets_and_show_upload)

    def rebuild_core_widgets_and_show_upload(self):
        logging.info("🔁 Membangun ulang UploadWidget & AnalysisProgressWidget...")
        
        old_upload_widget = self.stack.widget(1)
        if old_upload_widget:
            self.stack.removeWidget(old_upload_widget)
            old_upload_widget.deleteLater()
        
        self.upload_widget = UploadWidget()
        self.stack.insertWidget(1, self.upload_widget)
        if hasattr(self.upload_widget, 'reset_fields') and callable(self.upload_widget.reset_fields):
            self.upload_widget.reset_fields()
        logging.info("UploadWidget baru dibuat dan dimasukkan ke stack pada index 1.")

        old_analysis_widget = self.stack.widget(3)
        if old_analysis_widget:
            self.stack.removeWidget(old_analysis_widget)
            old_analysis_widget.deleteLater()

        self.analysis_widget = AnalysisProgressWidget(on_analysis_complete=self._safe_switch_to_summary)
        self.stack.insertWidget(3, self.analysis_widget)
        logging.info("AnalysisProgressWidget baru dibuat dan dimasukkan ke stack pada index 3.")
        
        self.stack.setCurrentWidget(self.upload_widget)
        self.fade_in_widget(self.upload_widget)
        logging.info("✅ Widget inti telah dibangun ulang. Tampilan saat ini: UploadWidget.")

    # --- Fungsi Utilitas Animasi ---
    def fade_in_widget(self, widget, duration=300): # Durasi default 300ms
        if widget is None: return
        try:
            effect = QGraphicsOpacityEffect(widget)
            widget.setGraphicsEffect(effect)
            # Gunakan widget sebagai parent animasi agar terkelola siklus hidupnya
            anim = QPropertyAnimation(effect, b"opacity", widget) 
            anim.setDuration(duration)
            anim.setStartValue(0.0) # Mulai dari transparan
            anim.setEndValue(1.0)   # Selesai di opaque
            # Hapus animasi dan efek setelah selesai untuk performa dan kebersihan
            anim.finished.connect(lambda: widget.setGraphicsEffect(None) if effect == widget.graphicsEffect() else None)
            anim.start(QPropertyAnimation.DeleteWhenStopped) # Hapus objek animasi setelah selesai
        except Exception as e:
            logging.error(f"MainWindow: Gagal menjalankan fade_in_widget untuk {widget}: {e}")

    def fade_out_widget(self, widget, on_finished_callback=None, duration=300): # Durasi default 300ms
        if widget is None: 
            if on_finished_callback: on_finished_callback()
            return
        try:
            effect = QGraphicsOpacityEffect(widget)
            widget.setGraphicsEffect(effect)
            # Gunakan widget sebagai parent animasi
            anim = QPropertyAnimation(effect, b"opacity", widget)
            anim.setDuration(duration)
            anim.setStartValue(1.0) # Mulai dari opaque
            anim.setEndValue(0.0)   # Selesai di transparan
            
            if on_finished_callback:
                anim.finished.connect(on_finished_callback)
            
            # Penting: Hapus efek setelah animasi selesai agar widget dapat menerima event
            # dan tidak ada sisa efek transparan yang mengganggu.
            # Pastikan kita hanya menghapus efek yang kita pasang.
            current_effect = widget.graphicsEffect() # Simpan referensi efek saat ini
            anim.finished.connect(lambda: widget.setGraphicsEffect(None) if widget.graphicsEffect() == current_effect else None)
            anim.start(QPropertyAnimation.DeleteWhenStopped) # Hapus objek animasi setelah selesai
        except Exception as e:
            logging.error(f"MainWindow: Gagal menjalankan fade_out_widget untuk {widget}: {e}")