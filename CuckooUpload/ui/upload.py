from PyQt5.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QPushButton, QFileDialog,
    QSizePolicy
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QDragEnterEvent, QDropEvent
from submitter import submit_to_cuckoo
import subprocess
import os
import logging

class UploadWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.current_uploaded_file = None

        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #f0f0f0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
            }
            QPushButton {
                background-color: #0078d7;
                color: white;
                padding: 10px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #005fa3;
            }
            QLabel#dropArea {
                border: 2px dashed #888;
                border-radius: 12px;
                padding: 35px;
                margin-bottom: 10px;
                color: #bbb;
            }
        """)

        self.label = QLabel("📂 Drag & Drop file here")
        self.label.setObjectName("dropArea")
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.button = QPushButton("Choose File")
        self.button.clicked.connect(self.open_file_dialog)

        self.status = QLabel("")
        self.status.setAlignment(Qt.AlignCenter)
        self.status.setStyleSheet("color: #aaaaaa; font-size: 13px;")

        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addWidget(self.label)
        layout.addWidget(self.button)
        layout.addWidget(self.status)
        self.setLayout(layout)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.process_file(file_path)

    def open_file_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.process_file(file_path)

    def process_file(self, file_path):
        logging.info(f"UploadWidget: Memproses file: {file_path}")
        if not os.path.isfile(file_path) or os.path.getsize(file_path) == 0:
            self.status.setText("❌ File tidak valid atau kosong.")
            self.status.setStyleSheet("color: red;")
            logging.warning(f"UploadWidget: File tidak valid atau kosong: {file_path}")
            return

        self.current_uploaded_file = file_path

        self.status.setText("📤 Mengirim file ke sandbox...")
        self.status.setStyleSheet("color: #ffaa00;")
        self.button.setEnabled(False)

        try:
            submit_to_cuckoo(file_path, self.status, None)
            logging.info(f"UploadWidget: submit_to_cuckoo selesai untuk {file_path}")
        except Exception as e:
            logging.error(f"UploadWidget: Error saat submit_to_cuckoo: {e}", exc_info=True)
            self.status.setText(f"❌ Error saat mengirim: {e}")
            self.status.setStyleSheet("color: red;")
            self.button.setEnabled(True)
            return

        self.run_dynamic_analysis()

        self.status.setText("📊 Analisis dan pembuatan laporan dimulai...")
        self.status.setStyleSheet("color: #00ff99;")
        logging.info("UploadWidget: Pembuatan laporan (analisis dinamis) dimulai.")

        main_window = self.window()
        if main_window:
            if hasattr(main_window, "handle_file_upload_success") and callable(main_window.handle_file_upload_success):
                logging.info("UploadWidget: Memanggil main_window.handle_file_upload_success()")
                print("UploadWidget: Memanggil main_window.handle_file_upload_success()")
                main_window.handle_file_upload_success()

    def run_dynamic_analysis(self):
        try:
            file_path = self.current_uploaded_file
            if not file_path:
                raise Exception("File belum dipilih.")

            cuckoo_cli = "/home/cuckoo/cuckoo3/venv/bin/cuckoo"  # path ke cuckoo CLI
            logging.info(f"Menjalankan: {cuckoo_cli} submit {file_path}")
            subprocess.Popen([cuckoo_cli, "submit", file_path])
        except Exception as e:
            logging.error(f"Gagal menjalankan cuckoo submit: {e}", exc_info=True)
            print(f"❌ Gagal menjalankan cuckoo submit: {e}")
            self.status.setText("❌ Error saat menjalankan analisis dinamis.")
            self.status.setStyleSheet("color: red;")
            self.button.setEnabled(True)

    def reset_fields(self):
        logging.info("UploadWidget: Mereset tampilan (reset_fields dipanggil).")
        print("UploadWidget: reset_fields() dipanggil")
        self.label.setText("📂 Drag & Drop file here")
        self.status.setText("")
        self.button.setEnabled(True)