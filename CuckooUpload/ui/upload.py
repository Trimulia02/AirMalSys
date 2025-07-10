from PyQt5.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QPushButton, QFileDialog,
    QSizePolicy
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QDragEnterEvent, QDropEvent
from submitter import submit_to_cuckoo
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
        logging.info(f"UploadWidget: Processing file: {file_path}")
        self.status.setText("📤 Sending file to sandbox...")
        self.status.setStyleSheet("color: #ffaa00;")
        self.button.setEnabled(False)

        success, message = submit_to_cuckoo(file_path)
        self.status.setText(message)

        if success:
            self.status.setStyleSheet("color: #00ff99;")
            self.current_uploaded_file = file_path

            # ✅ Trigger animation only if submit was successful
            main_window = self.window()
            if main_window and hasattr(main_window, "handle_file_upload_success"):
                logging.info("UploadWidget: Calling handle_file_upload_success() because submission succeeded.")
                main_window.handle_file_upload_success()
        else:
            self.status.setStyleSheet("color: red;")
            self.button.setEnabled(True)
            logging.warning("UploadWidget: Submission failed. Animation not triggered.")

    def reset_fields(self):
        logging.info("UploadWidget: Resetting UI fields (reset_fields called).")
        self.label.setText("📂 Drag & Drop file here")
        self.status.setText("")
        self.button.setEnabled(True)
